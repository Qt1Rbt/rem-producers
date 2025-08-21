#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <curl/curl.h>
#include <hiredis/hiredis.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <unistd.h>
#include <signal.h>

#define DEFAULT_EVENT_URL "http://192.168.11.46/ISAPI/Event/notification/alertStream"
#define DEFAULT_USERNAME "admin"
#define DEFAULT_PASSWORD "PWD"
#define TRIGGER_CURL_TIMEOUT_SECONDS 5L
#define MAX_CHANNELS 32
#define TRIGGER_MIN_INTERVAL 120

typedef struct
{
    char *eventState;
    char *dateTime;
    char *eventDescription;
    char *ruleTemperature;
    char *currTemperature;
    char *ruleType;
    char *ruleCalibType;
    char *channelID;
    char *visibleLightURL;
    char *thermalURL;
} Event;

typedef struct
{
    time_t lastTrigger;
    double lastTemp;
} ChannelState;

static ChannelState channels[MAX_CHANNELS];
static int test_mode = 0;

static volatile sig_atomic_t stop_flag = 0;

void handle_signal(int sig)
{
    (void)sig;
    stop_flag = 1;
}

static xmlChar *get_xml_node_text(xmlNode *node)
{
    xmlChar *txt = xmlNodeGetContent(node);
    return txt;
}

static char *dup_or_empty(xmlChar *txt)
{
    if (!txt)
        return strdup("");

    char *out = strdup((char *)txt);
    xmlFree(txt);

    if (!out) //TODO handle memory allocation failure
        return strdup("");

    return out;
}

typedef struct {
    const char *xml_name;
    size_t offset;
} FieldMap;

#define FIELD_ENTRY(field) { #field, offsetof(Event, field) }

static FieldMap event_fields[] = {
    FIELD_ENTRY(eventState),
    FIELD_ENTRY(dateTime),
    FIELD_ENTRY(eventDescription),
    FIELD_ENTRY(channelID),
    FIELD_ENTRY(visibleLightURL),
    FIELD_ENTRY(thermalURL),
    {NULL, 0}
};

static FieldMap temp_rules_fields[] = {
    FIELD_ENTRY(ruleTemperature),
    FIELD_ENTRY(currTemperature),
    FIELD_ENTRY(ruleType),
    FIELD_ENTRY(ruleCalibType),
    {NULL, 0}
};

static Event *parse_event_xml(const char *xml)
{
    xmlDocPtr doc = xmlReadMemory(xml, strlen(xml), "noname.xml", NULL, XML_PARSE_NOBLANKS | XML_PARSE_NONET);
    if (!doc)
        return NULL;

    xmlNode *root = xmlDocGetRootElement(doc);
    if (!root)
    {
        xmlFreeDoc(doc);
        return NULL;
    }

    Event *ev = calloc(1, sizeof(Event));
    if (!ev)
    {
        //TODO handle memory allocation failure
        xmlFreeDoc(doc);
        return NULL;
    }

    for (xmlNode *node = root->children; node; node = node->next)
    {
        if (node->type != XML_ELEMENT_NODE)
            continue;
        // Top-level Event fields
        for (FieldMap *fm = event_fields; fm->xml_name; ++fm) {
            if (xmlStrcmp(node->name, (const xmlChar *)fm->xml_name) == 0) {
                char **field_ptr = (char **)((char *)ev + fm->offset);
                *field_ptr = dup_or_empty(get_xml_node_text(node));

                // goto next_node; break current loop and ignore next comparisons
                goto next_node;
            }
        }

        // DetectionRegionList special handling
        if (xmlStrcmp(node->name, (const xmlChar *)"DetectionRegionList") == 0) {

            const char *temp_rule_node = NULL;
            if (ev->eventDescription && strcmp(ev->eventDescription, "Temperature Measurement Precautionary Alarm") == 0)
                temp_rule_node = "TMPA";
            else if (ev->eventDescription && strcmp(ev->eventDescription, "Temperature Measurement Alarm") == 0)
                temp_rule_node = "TMA";

            // DetectionRegionEntry parsing
            for (xmlNode *dre = node->children; dre; dre = dre->next) {
                if (dre->type != XML_ELEMENT_NODE)
                    continue;
                for (xmlNode *temp_rule = dre->children; temp_rule; temp_rule = temp_rule->next)
                {
                    if (temp_rule->type != XML_ELEMENT_NODE)
                        continue;

                    // TMPA fields / TMA fields (depending on description)
                    if (xmlStrcmp(temp_rule->name, (const xmlChar *)temp_rule_node) == 0) {
                        for (xmlNode *field = temp_rule->children; field; field = field->next) {
                            if (field->type != XML_ELEMENT_NODE)
                                continue;
                            for (FieldMap *tf = temp_rules_fields; tf->xml_name; ++tf)
                            {
                                if (xmlStrcmp(field->name, (const xmlChar *)tf->xml_name) == 0) {
                                    char **field_ptr = (char **)((char *)ev + tf->offset);
                                    *field_ptr = dup_or_empty(get_xml_node_text(field));
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    next_node:;
    }

    xmlFreeDoc(doc);
    return ev;
}

static void free_event(Event *ev)
{
    if (!ev)
        return;
    free(ev->eventState);
    free(ev->dateTime);
    free(ev->eventDescription);
    free(ev->ruleTemperature);
    free(ev->currTemperature);
    free(ev->ruleType);
    free(ev->ruleCalibType);
    free(ev->channelID);
    free(ev->visibleLightURL);
    free(ev->thermalURL);
    free(ev);
}

static void process_event(const char *xml_chunk)
{
    Event *ev = parse_event_xml(xml_chunk);
    if (!ev)
        return;

    if (strcmp(ev->eventDescription, "Temperature Measurement Alarm") != 0 &&
        strcmp(ev->eventDescription, "Temperature Measurement Precautionary Alarm") != 0)
    {
        free_event(ev);
        return;
    }

    if (strcmp(ev->eventState, "active") != 0)
    {
        free_event(ev);
        return;
    }

    char *endptr = NULL;
    long cid = strtol(ev->channelID ? ev->channelID : "0", &endptr, 10);
    if (endptr == ev->channelID || *endptr != '\0' || cid <= 0)
    {
        free_event(ev);
        return;
    }

    int should_trigger = 0;
  
    int idx = cid - 1;
    if (idx < 0 || idx >= MAX_CHANNELS) {
        free_event(ev);
        return;
    }

    // Parse currTemperature as double
    double currTemp = 0.0;
    if (ev->currTemperature && *ev->currTemperature) {
        currTemp = strtod(ev->currTemperature, NULL);
    }

    // Allow new event if interval or temp delta > 20
    time_t now = time(NULL);
    double tempDelta = fabs(currTemp - channels[idx].lastTemp);
    if (difftime(now, channels[idx].lastTrigger) > TRIGGER_MIN_INTERVAL || tempDelta > 20.0) {
        should_trigger = 1;
        channels[idx].lastTrigger = now;
        channels[idx].lastTemp = currTemp;
    }
    
    if (should_trigger) {
        char json[2048];
        snprintf(json, sizeof(json),
            "{"
            "\"eventState\":\"%s\"," 
            "\"dateTime\":\"%s\"," 
            "\"eventDescription\":\"%s\"," 
            "\"ruleTemperature\":\"%s\"," 
            "\"currTemperature\":\"%s\"," 
            "\"ruleType\":\"%s\"," 
            "\"ruleCalibType\":\"%s\"," 
            "\"channelID\":%s," 
            "\"visibleLightURL\":\"%s\"," 
            "\"thermalURL\":\"%s\""
            "}",
           ev->eventState,ev->dateTime,ev->eventDescription,
           ev->ruleTemperature,ev->currTemperature,
           ev->ruleType,ev->ruleCalibType,
           ev->channelID,ev->visibleLightURL,ev->thermalURL
        );

        if (test_mode) {
            printf("[TEST MODE] Would push to Redis: %s\n", json);
            free_event(ev);
            return;
        }

        printf("Push to Redis: %s\n", json);
        fflush(stdout);
        const char *redis_host = getenv("REDIS_HOST");
        if (!redis_host) redis_host = "127.0.0.1";
        redisContext *c = redisConnect(redis_host, 6379);
        if (c == NULL || c->err) {
            if (c) {
                fprintf(stderr, "Redis connection error: %s\n", c->errstr);
                redisFree(c);
            } else {
                fprintf(stderr, "Redis connection error: can't allocate context\n");
            }
            free_event(ev);
            return;
        }

        redisReply *reply = redisCommand(c, "RPUSH events %s", json);
        if (!reply) {
            fprintf(stderr, "Redis RPUSH to 'events' failed\n");
            redisFree(c);
            free_event(ev);
            return;
        }
        freeReplyObject(reply);

        // Push to the second queue 'pending_downloads'
        reply = redisCommand(c, "RPUSH pending_downloads %s", json);
        if (!reply) {
            fprintf(stderr, "Redis RPUSH to 'pending_downloads' failed\n");
            redisFree(c);
            free_event(ev);
            return;
        }
        freeReplyObject(reply);
        redisFree(c);
    }

    free_event(ev);
}

typedef struct
{
    char *data;
    size_t len;
} StreamBuf;

static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    StreamBuf *buf = userdata;
    size_t total = size * nmemb;
    const char *BOUNDARY = "--boundary";

    // Grow buffer
    char *new_data = realloc(buf->data, buf->len + total + 1);
    if (!new_data)
    {
        fprintf(stderr, "Memory allocation failed\n");
        return 0;
    }
    buf->data = new_data;

    memcpy(buf->data + buf->len, ptr, total);
    buf->len += total;
    buf->data[buf->len] = '\0';

    // Process while we can find complete boundaries
    char *start = buf->data;
    for (;;)
    {
        char *boundary_pos = strstr(start, BOUNDARY);
        if (!boundary_pos)
            break; // No complete block yet

        char *next_boundary = strstr(boundary_pos + strlen(BOUNDARY), BOUNDARY);
        if (!next_boundary)
            break; // Incomplete block

        // Extract block content
        char *content_start = strstr(boundary_pos, "\r\n\r\n");
        if (!content_start)
        {
            content_start = strstr(boundary_pos, "\n\n");
            if (!content_start)
            {
                start = next_boundary;
                continue;
            }
        }
        content_start += (content_start[1] == '\n' ? 2 : 4);

        // Length is until next boundary minus CRLF
        size_t xml_len = (size_t)(next_boundary - content_start);
        while (xml_len > 0 && (content_start[xml_len - 1] == '\n' || content_start[xml_len - 1] == '\r'))
            xml_len--;

        char *xml_chunk = malloc(xml_len + 1);
        if (!xml_chunk)
        {
            fprintf(stderr, "Memory allocation failed\n");
            return 0;
        }
        memcpy(xml_chunk, content_start, xml_len);
        xml_chunk[xml_len] = '\0';

        // Trim CR/LF before XML
        while (xml_len > 0 && (xml_chunk[0] == '\n' || xml_chunk[0] == '\r'))
        {
            memmove(xml_chunk, xml_chunk + 1, xml_len);
            xml_len--;
        }
        xml_chunk[xml_len] = '\0';

        // fprintf(stderr, "Processing XML chunk: %s\n", xml_chunk);
        process_event(xml_chunk);
        // fprintf(stderr, "End Processing XML chunk\n");
        free(xml_chunk);

        start = next_boundary;
    }

    // Keep only unprocessed data in buffer
    size_t remaining = buf->len - (start - buf->data);
    memmove(buf->data, start, remaining);
    buf->len = remaining;
    buf->data[buf->len] = '\0';

    return total;
}

static void run_normal_mode(const char *event_url, const char *username, const char *password) {
    StreamBuf sb = {0};
    while (!stop_flag)
    {
        fprintf(stderr, "Connecting to %s with user %s\n", event_url, username);
        CURL *curl = curl_easy_init();
        curl_easy_setopt(curl, CURLOPT_URL, event_url);
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_DIGEST);
        curl_easy_setopt(curl, CURLOPT_USERNAME, username);
        curl_easy_setopt(curl, CURLOPT_PASSWORD, password);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &sb);
        curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 0L);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);

        CURLcode res = curl_easy_perform(curl);
        long http_code = 0;
        fprintf(stderr, "Trying to retreive response code\n");
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        if (res != CURLE_OK) {
            fprintf(stderr, "stream error: %s\n", curl_easy_strerror(res));
        } else if (http_code < 200 || http_code >= 300) {
            fprintf(stderr, "HTTP error: status code %ld\n", http_code);
            break;
        }
        curl_easy_cleanup(curl);
        sleep(1);
    }
}

int main(int argc, char **argv)
{
    // Setup signal handlers for graceful shutdown
    struct sigaction sa;
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    
    const char *username = (argc > 1) ? argv[1] : DEFAULT_USERNAME;
    const char *password = (argc > 2) ? argv[2] : DEFAULT_PASSWORD;
    const char *event_url = (argc > 3) ? argv[3] : DEFAULT_EVENT_URL;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--test") == 0) {
            test_mode = 1;
        }
    }

    curl_global_init(CURL_GLOBAL_DEFAULT);
    xmlInitParser();
    memset(channels, 0, sizeof(channels));

    if (test_mode) {
        return 1;
        // run_test_mode();
    } else {
        run_normal_mode(event_url, username, password);
    }

    // Graceful shutdown message
    fprintf(stderr, "\nShutting down gracefully...\n");
    curl_global_cleanup();
    xmlCleanupParser();
    return 0;
}
