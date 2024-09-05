#ifndef _SETIFACE_H
    #define _SETIFACE_H

    #ifdef SETIFACE_IMPORT_HDR
        #include <stdio.h>
        #include <unistd.h>
        #include <string.h>
        #include <sys/ioctl.h>

        #include <net/if.h>
        #include <netinet/in.h>

        #include <linux/if.h>
    #endif

    int set_iface_params(const char *dev, int codeset);
#endif