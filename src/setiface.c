#define _DEFAULT_SOURCE

#define SETIFACE_IMPORT_HDR
#include "../include/setiface.h"

int IS_UP_DOWN = 0; // was the interface brought down and back up?

int set_iface_params(const char *dev, int codeset)
{
    int sockfd;
    struct ifreq ifr;

    // create socket to perform ioctl calls upon
    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    // zero out
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_ifrn.ifrn_name, dev, IFNAMSIZ - 1);

    // obtain the current flags
    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0)
    {
        fprintf(stderr, "\n\033[0;31mERROR\033[0;m Failed to obtain the current flags for interface %s! It probably does not exist...\n", dev);
        close(sockfd);

        return -1;
    }

    // has valid interface identifier
    // this is shotty as it does not currently validate a list of available network interfaces to manage/work with
    printf("++ Valid interface \"%s\" set as primary NIC for remote wireless reconnaissance\n", dev);

    if (codeset)
    {
        ifr.ifr_ifru.ifru_flags |= IFF_UP;
    }
    else
    {
        ifr.ifr_ifru.ifru_flags &= ~IFF_UP;
    }

    // set the modified flags
    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0)
    {
        close(sockfd);

        uid_t uid = getuid();

        if (uid != 0x0)
        {
            fprintf(stderr, "\n\033[0;31mERROR\033[0;m Failed because running operations like this requires root privileges. Run with \"sudo -E\"...\n");
        }

        return -1;
    }

    IS_UP_DOWN++;

    if (IS_UP_DOWN == 2)
    {
        printf("\n\033[0;32mSUCCESS\033[0;m Wireless interface set for monitor mode, pushing function execution relays to the foreground...\n");
        printf("Press <ENTER> to continue...\n\n"); getchar();

        // setting getchar() seems to be buffering packets waiting in a queue
    }

    close(sockfd);

    return 0;
}