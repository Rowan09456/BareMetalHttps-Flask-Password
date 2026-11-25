#include <cstdio>
#include <cstring>
#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"
#include "lwip/altcp_tls.h"
#include "lwip/ip_addr.h"
#include "mbedtls/ssl.h"
#include "secrets.h"


static struct altcp_tls_config *tls_config = nullptr;
static bool request_done = false;

static void close_tls_pcb(struct altcp_pcb *pcb) {
    if (pcb) {
        altcp_arg(pcb, nullptr);
        altcp_recv(pcb, nullptr);
        altcp_err(pcb, nullptr);
        altcp_close(pcb);
    }
    if (tls_config) {
        altcp_tls_free_config(tls_config);
        tls_config = nullptr;
    }
    request_done = true;
}

static void on_tls_err(void *arg, err_t err) {
    printf("TLS/TCP error: %d\n", err);
    if (tls_config) {
        altcp_tls_free_config(tls_config);
        tls_config = nullptr;
    }
    request_done = true;
}

static err_t on_tls_recv(void *arg, struct altcp_pcb *pcb, struct pbuf *p, err_t err) {
    if (!p) {
        // Server closed connection (end of HTTP response)
        printf("\n--- Connection closed by Flask server ---\n");
        close_tls_pcb(pcb);
        return ERR_OK;
    }

    // Print chunked or full HTTP response
    for (struct pbuf *q = p; q != nullptr; q = q->next) {
        printf("%.*s", q->len, static_cast<char *>(q->payload));
    }

    altcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    return ERR_OK;
}

static err_t on_tls_connected(void *arg, struct altcp_pcb *pcb, err_t err) {
    if (err != ERR_OK) {
        printf("Handshake failed: %d\n", err);
        close_tls_pcb(pcb);
        return err;
    }

    printf("TLS handshake succeeded! Sending GET request...\n");
    const char *http_req =
        "GET /passwd HTTP/1.1\r\n"
        "Host: " FLASK_IP "\r\n"
        "Connection: close\r\n\r\n";

    err_t write_err = altcp_write(pcb, http_req, strlen(http_req), TCP_WRITE_FLAG_COPY);
    if (write_err == ERR_OK) {
        altcp_output(pcb);
    } else {
        printf("Write error: %d\n", write_err);
        close_tls_pcb(pcb);
    }
    return ERR_OK;
}

void send_https_get() {
    ip_addr_t server_ip;
    if (!ipaddr_aton(FLASK_IP, &server_ip)) {
        printf("Invalid IP address\n");
        return;
    }

    // Lock lwIP thread when calling altcp APIs from main loop
    cyw43_arch_lwip_begin();

    // Passing NULL, 0 disables Root CA verification
    tls_config = altcp_tls_create_config_client(nullptr, 0);
    struct altcp_pcb *pcb = altcp_tls_new(tls_config, IPADDR_TYPE_V4);

    if (!pcb) {
        printf("Failed to allocate TLS PCB\n");
        cyw43_arch_lwip_end();
        return;
    }

    // Optional when connecting via raw IP, harmless to include
    mbedtls_ssl_set_hostname(static_cast<mbedtls_ssl_context *>(altcp_tls_context(pcb)), FLASK_IP);

    altcp_recv(pcb, on_tls_recv);
    altcp_err(pcb, on_tls_err);

    err_t err = altcp_connect(pcb, &server_ip, FLASK_PORT, on_tls_connected);
    cyw43_arch_lwip_end();

    if (err != ERR_OK) {
        printf("altcp_connect failed immediately: %d\n", err);
    }
}

int main() {
    stdio_init_all();
    sleep_ms(2000);

    if (cyw43_arch_init()) {
        printf("CYW43 init failed\n");
        return 1;
    }

    int in = getchar_timeout_us(0); // Clear any pending input
    while(in != 'c')
    {
        printf("Press 'c' to start HTTP client...\n");
        in = getchar_timeout_us(0);
        sleep_ms(1000);
        cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN,!cyw43_arch_gpio_get(CYW43_WL_GPIO_LED_PIN)); // Toggle LED
    }

    cyw43_arch_enable_sta_mode();
    printf("Connecting to Wi-Fi...\n");
    if (cyw43_arch_wifi_connect_timeout_ms(WIFI_SSID, WIFI_PASSWORD, CYW43_AUTH_WPA2_AES_PSK, 30000)) {
        printf("Wi-Fi connection failed\n");
        return 1;
    }
    
    while(true)
    {
        printf("Connected! Making HTTPS request to Flask...\n");
        send_https_get();

        while (!request_done) {
            sleep_ms(100);
            cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN,!cyw43_arch_gpio_get(CYW43_WL_GPIO_LED_PIN));
        }
        
        for (int i = 0; i < 5; i++)     
        {
            printf("Waiting 5 seconds between http requests... (%d/5)\n", i + 1);
            sleep_ms(1000);
            cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN,!cyw43_arch_gpio_get(CYW43_WL_GPIO_LED_PIN)); // Toggle LED
        }
    
    }

    

    cyw43_arch_deinit();
    return 0;
}
