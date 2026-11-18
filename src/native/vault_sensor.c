/*
 * vault_sensor.c - Native USB Trust Inventory, Intel ISH ToF & BT Security Probe
 * Detects new HID keyboards / USB storage (BadUSB candidates) and reads ToF radar.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dirent.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static bool read_line(const char *path, char *out, size_t sz) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;
    ssize_t n = read(fd, out, sz - 1);
    close(fd);
    if (n <= 0) return false;
    out[n] = '\0';
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r' || out[n - 1] == ' ')) {
        out[--n] = '\0';
    }
    return true;
}

static void json_esc(const char *s, char *out, size_t sz) {
    size_t j = 0;
    for (size_t i = 0; s && s[i] && j + 2 < sz; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"' || c == '\\') {
            if (j + 2 >= sz) break;
            out[j++] = '\\'; out[j++] = (char)c;
        } else if (c >= 0x20) {
            out[j++] = (char)c;
        }
    }
    out[j] = '\0';
}

typedef struct {
    char port[32];
    char vid[8];
    char pid[8];
    char product[64];
    char devclass[8];
    bool hid_or_storage;
} UsbEntry;

static bool port_has_hid_or_storage(const char *port) {
    DIR *d = opendir("/sys/bus/usb/devices");
    if (!d) return false;
    size_t plen = strlen(port);
    struct dirent *de;
    bool hit = false;
    while ((de = readdir(d)) != NULL) {
        if (strncmp(de->d_name, port, plen) != 0 || de->d_name[plen] != ':') continue;
        char cp[320], cls[16] = "";
        snprintf(cp, sizeof(cp), "/sys/bus/usb/devices/%.64s/bInterfaceClass", de->d_name);
        if (read_line(cp, cls, sizeof(cls))) {
            if (strcmp(cls, "03") == 0 || strcmp(cls, "08") == 0) {
                hit = true;
                break;
            }
        }
    }
    closedir(d);
    return hit;
}

int main(int argc, char *argv[]) {
    bool as_json = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0 || strcmp(argv[i], "-j") == 0) as_json = true;
    }

    UsbEntry usbs[32];
    size_t nusb = 0;
    DIR *ud = opendir("/sys/bus/usb/devices");
    if (ud) {
        struct dirent *de;
        while ((de = readdir(ud)) != NULL && nusb < 32) {
            if (de->d_name[0] == '.' || strncmp(de->d_name, "usb", 3) == 0 || strchr(de->d_name, ':')) continue;
            char vp[320], pp[320], prp[320], cp[320];
            UsbEntry *u = &usbs[nusb];
            memset(u, 0, sizeof(*u));
            snprintf(u->port, sizeof(u->port), "%.31s", de->d_name);
            snprintf(vp, sizeof(vp), "/sys/bus/usb/devices/%.64s/idVendor", de->d_name);
            snprintf(pp, sizeof(pp), "/sys/bus/usb/devices/%.64s/idProduct", de->d_name);
            snprintf(prp, sizeof(prp), "/sys/bus/usb/devices/%.64s/product", de->d_name);
            snprintf(cp, sizeof(cp), "/sys/bus/usb/devices/%.64s/bDeviceClass", de->d_name);
            if (!read_line(vp, u->vid, sizeof(u->vid))) continue;
            read_line(pp, u->pid, sizeof(u->pid));
            if (!read_line(prp, u->product, sizeof(u->product))) snprintf(u->product, sizeof(u->product), "USB Peripheral");
            read_line(cp, u->devclass, sizeof(u->devclass));
            u->hid_or_storage = port_has_hid_or_storage(u->port);
            nusb++;
        }
        closedir(ud);
    }

    /* Check ToF telemetry from shared Intel ISH stream */
    char tof_state[32] = "offline";
    int dist_cm = 0, thresh_cm = 120;
    FILE *tf = fopen("/run/ff-power-manager/sensor_telemetry.json", "r");
    if (tf) {
        char buf[1024];
        size_t n = fread(buf, 1, sizeof(buf) - 1, tf);
        fclose(tf);
        buf[n] = '\0';
        char *p = strstr(buf, "\"state\":");
        if (p) sscanf(p, "\"state\":%*[^a-zA-Z]%31[a-zA-Z]", tof_state);
        p = strstr(buf, "\"distance_cm\":");
        if (p) sscanf(p, "\"distance_cm\":%d", &dist_cm);
        p = strstr(buf, "\"threshold_cm\":");
        if (p) sscanf(p, "\"threshold_cm\":%d", &thresh_cm);
    }

    int bt_hci = (access("/sys/class/bluetooth/hci0", F_OK) == 0) ? 1 : 0;

    if (as_json) {
        char st_e[48];
        json_esc(tof_state, st_e, sizeof(st_e));
        printf("{\n"
               "  \"tof\": {\"state\": \"%s\", \"distance_cm\": %d, \"threshold_cm\": %d},\n"
               "  \"bluetooth_ready\": %s,\n"
               "  \"usb_devices\": [",
               st_e, dist_cm, thresh_cm, bt_hci ? "true" : "false");
        for (size_t i = 0; i < nusb; i++) {
            char pe[128];
            json_esc(usbs[i].product, pe, sizeof(pe));
            printf("%s\n    {\"port\": \"%s\", \"id\": \"%s:%s\", \"product\": \"%s\", \"class\": \"%s\", \"hid_or_storage\": %s}",
                   i == 0 ? "" : ",", usbs[i].port, usbs[i].vid, usbs[i].pid, pe, usbs[i].devclass,
                   usbs[i].hid_or_storage ? "true" : "false");
        }
        printf("\n  ]\n}\n");
    } else {
        printf("=== Waylens Privacy Zero-Trust Perimeter ===\n");
        printf("  ToF Radar : %s (%d / %d cm)\n", tof_state, dist_cm, thresh_cm);
        printf("  Bluetooth : %s | USB Enumerated: %zu devices\n", bt_hci ? "hci0 ready" : "none", nusb);
        for (size_t i = 0; i < nusb; i++) {
            printf("    [%s] %s:%s %s%s\n", usbs[i].port, usbs[i].vid, usbs[i].pid, usbs[i].product,
                   usbs[i].hid_or_storage ? " [HID/Storage]" : "");
        }
    }
    return 0;
}
