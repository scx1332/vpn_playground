#include <stdlib.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>

#include <stdio.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#ifdef DEBUG
#define debug_print(fmt, ...) \
            do { fprintf(stderr, fmt, ##__VA_ARGS__); } while (0)
#else 
#define debug_print(fmt, ...) do { } while(0)
#endif

static int tun_alloc(char *dev, int flags);

#ifdef USE_MD5
#include <openssl/md5.h>
uint64_t hash_str(const char *str) {
  MD5_CTX c;
  union {
    unsigned char digest[16];
    uint64_t retv;
  } v;

  MD5_Init(&c);
  MD5_Update(&c, str, strlen(str));
  MD5_Final(v.digest, &c);

  return v.retv;
}
#else 
uint64_t hash_str(const char *str, int n) {
  uint64_t data = 0x0101010101010101ull;
  int minv = 0;
  while (minv<16) {
    for (int i=0; i<n && str[i]; ++i) {
      data = data * 13 + ((uint8_t)str[i]);
      minv+=1;
    }
  }
  return data;
}
#endif 
enum msg_code {
  MT_NOOP = 0,
  MT_INIT = 1,
  MT_ALLOC = 2,
  MT_FORWARD = 3,
  MT_KEEP = 4,
};

struct mt_noop {
  uint8_t op;
};

struct mt_init {
  uint8_t op; //=1
  uint64_t id; 
};

struct mt_alloc {
  uint8_t op; // =2
  uint32_t network;
  uint32_t mask;
};

struct mt_forward {
  uint8_t op; // = 3
  uint8_t bytes[0];
};

struct mt_keep {
  uint8_t op; // = 4
  uint32_t addr;
  uint64_t id;
};

typedef union mt_all {
  uint8_t op;
  struct mt_noop noop;
  struct mt_init init;
  struct mt_alloc alloc;
  struct mt_forward forward;
  struct mt_keep keep;
} mt_all;


static uint8_t alloc_client(uint64_t clients[], uint64_t id) {
  uint8_t idx = (id & 0xff) ^ ((id >> 8)&0xff) ^ ((id>>16)&0xff) ^ ((id>>24)&0xff);
  int retry = 5;

  while (retry > 0 && clients[idx]!=0 && (idx <1||idx>250) && clients[idx] != id) {
    idx+=13;
  }
  return idx;
}

static int novpn_server(uint16_t port, uint32_t net, uint32_t mask) {
 
  // udp
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
      perror("server socket");
      return -1;
  }
  struct sockaddr_in servaddr;
  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family    = AF_INET;
  servaddr.sin_addr.s_addr = INADDR_ANY;
  servaddr.sin_port = htons(port);
  if ( bind(fd, (const struct sockaddr *)&servaddr,  sizeof(servaddr)) < 0 ) {
    perror("bind server");
    return -1;
  }
  uint64_t clients[256];
  struct sockaddr_in client_addr[256];
  memset(clients, 0, sizeof(clients));

  for(;;) {
    struct sockaddr_in cli_addr;
    memset(&cli_addr, 0, sizeof(cli_addr));
    uint8_t buffer[2000];
    socklen_t len = sizeof(cli_addr);
    ssize_t n = recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&cli_addr, &len);
    if (n < 0) {
      perror("recvfrom");
      close(fd);
      return -1;
    }
    mt_all *p = (mt_all *)buffer;
    // reply to ping
    if (p->op == MT_NOOP) {
      sendto(fd, buffer, n, 0, (struct sockaddr *)&cli_addr, len);
      continue;
    }
    if (p->op == MT_INIT) {
      uint64_t id = p->init.id;
      uint8_t idx = alloc_client(clients, id);
      clients[idx] = id;
      memcpy(&client_addr[idx], &cli_addr, len);
      struct mt_alloc alloc = { MT_ALLOC,  net | idx, mask };
      sendto(fd, &alloc, sizeof(alloc), 0, (struct sockaddr *)&cli_addr, len);
      continue;
    }
    if (p->op == MT_KEEP) {
        uint8_t idx = p->keep.addr & 0xff;
        uint64_t id = p->keep.id;
        if (clients[idx] == 0) {
          idx = alloc_client(clients, p->keep.id);
          clients[idx] = id;
          memcpy(&client_addr[idx], &cli_addr, len);
          struct mt_alloc alloc = { MT_ALLOC,  net | idx, mask };
          sendto(fd, &alloc, sizeof(alloc), 0, (struct sockaddr *)&cli_addr, len);
          continue;
        }
        else {
          if (clients[idx] == id) {
            memcpy(&client_addr[idx], &cli_addr, len);          
          }
          struct mt_noop noop = { MT_NOOP };
          sendto(fd, &noop, sizeof(noop), 0, (struct sockaddr *)&cli_addr, len);          
          continue;
        }
    }
    if (p->op == MT_FORWARD) {
        struct iphdr *ip = (struct iphdr *)p->forward.bytes;
        if (ip->version != 4) {
          debug_print("reject no ipv4\n");
          continue;
        }
        uint32_t daddr = ntohl(ip->daddr);
        fprintf(stderr, "smok\n");
        if ((daddr & mask) != net) {
          debug_print("reject invalid dest: %0x (%04ux/%04x) \n", daddr, net, daddr & mask);
          continue;
        }
        uint32_t idx = daddr & 0xff;
        if (clients[idx] == 0) {
          debug_print("reject client not found for: %d\n", idx);
          continue;
        }
        sendto(fd, buffer, n, 0, (struct sockaddr *)&client_addr[idx], len);
        continue;
    }
    fprintf(stderr, "invalid packet!\n");
  }
  return 0;
}

static uint64_t genid() {
  char buffer[256];
  if (gethostname(buffer, sizeof(buffer)) == -1) {
      perror("gethostname");
      _exit(1);
  }
  return hash_str(buffer, sizeof(buffer));
}

static int novpn_client(const char *addr, uint16_t port) {
  uint64_t id = genid();
  in_addr_t server_addr = inet_addr(addr);

  if (server_addr == ((in_addr_t)(-1))) {
    fputs("invalid addr", stderr);
    return -1;
  }
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
      perror("client socket");
      return -1;
  }

  {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family    = AF_INET;
    addr.sin_addr.s_addr = server_addr;
    addr.sin_port = htons(port);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
      perror("connect");
      return -1;
    }
  }
  fprintf(stderr, "id=%lx\n", id);

  uint8_t buffer[2000];
  mt_all *p = (mt_all *)buffer;

  int tun_fd = -1;
  uint32_t alloc_addr = 0;
  struct ifreq req;

  for (;;) {
    {
      struct mt_init init = { MT_INIT, id };
      send(fd, &init, sizeof(init), 0);
    }

    int n = recv(fd, buffer, sizeof(buffer), 0);
    if (n < 0 ) {
      perror("recv");
      return -1;
    }
    fprintf(stderr, "got packet\n");
    if (p->op == MT_ALLOC) {
      fprintf(stderr, "allocation net=%04x mask=%04x\n", p->alloc.network, p->alloc.mask);
      alloc_addr = p->alloc.network;

      strncpy(req.ifr_name,"novpn", IFNAMSIZ);
      //  strcpy(tun_name, "novpn");
      tun_fd = tun_alloc(req.ifr_name, IFF_TUN | IFF_NO_PI);
      if (tun_fd < 0) {
        fprintf(stderr, "unable to alocate network interface\n");
        return -1;
      }
      memset(&req.ifr_addr, 0, sizeof(req.ifr_addr));
      {
        struct sockaddr_in *sin = (struct sockaddr_in *) &req.ifr_addr;
        sin->sin_family = AF_INET;
        sin->sin_port = 0;
        sin->sin_addr.s_addr = htonl(p->alloc.network);
        if (ioctl(fd, SIOCSIFADDR, &req) < 0) {
          perror("set addr");
          return -1;
        }
      }
      {
        struct sockaddr_in *sin = (struct sockaddr_in *) &req.ifr_netmask;
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = htonl(p->alloc.mask);
        if (ioctl(fd, SIOCSIFNETMASK, &req) < 0) {
          perror("set mask");
          return -1;
        }
        
      }
      req.ifr_mtu = 1300;
      if (ioctl(fd, SIOCSIFMTU, &req) < 0) {
        perror("set mtu");
        return -1;
      }

      if (ioctl(fd, SIOCGIFFLAGS, &req) < 0) {
        perror("flags");
        return -1;
      }
      req.ifr_flags |= IFF_UP;
      if (ioctl(fd, SIOCSIFFLAGS, &req) < 0) {
        perror("flags");
        return -1;
      }


      break;
    }
  }
  fd_set rs;
  FD_ZERO(&rs);
  int maxfd = 0;

  if (fd >= maxfd) {
    maxfd = fd+1;
  }
  if (tun_fd >= maxfd) {
    maxfd = tun_fd+1;
  }

  for (;;) {
    FD_SET(fd, &rs);
    FD_SET(tun_fd, &rs);
    struct timeval tv = { 10, 0 };
    int sn = select(maxfd, &rs, NULL, NULL, &tv);
    if (sn == -1) {
      perror("select");
      return -1;
    }
    if (sn == 0) {
      struct mt_keep keep = { MT_KEEP, alloc_addr, id };
      send(fd, &keep, sizeof(keep), 0);
    }
    if (FD_ISSET(tun_fd, &rs)) {
      int header = p->forward.bytes - buffer;
      int packet_length = read(tun_fd, p->forward.bytes, sizeof(buffer)-sizeof(struct mt_forward));
      p->op = MT_FORWARD;
      if (send(fd, buffer, packet_length + header, 0) < 0) {
        perror("send");
        return -1;
      }
    }
    if (FD_ISSET(fd, &rs)) {
      ssize_t len = recv(fd, buffer, sizeof(buffer), 0);
      if (len < 0) {
        perror("recv");
        return -1;
      }
      if (p->op == MT_FORWARD) {
        int header = p->forward.bytes - buffer;
        if (write(tun_fd, p->forward.bytes, len-header) < 0) {
          perror("packet send");
          return -1;
        }        
      }
      else if (p->op == MT_NOOP) {
        /* do nothing */
      }
      else if (p->op == MT_ALLOC) {
        alloc_addr = p->alloc.network;
        struct sockaddr_in *sin = (struct sockaddr_in *) &req.ifr_addr;
        sin->sin_family = AF_INET;
        sin->sin_port = 0;
        sin->sin_addr.s_addr = htonl(alloc_addr);
        if (ioctl(fd, SIOCSIFADDR, &req) < 0) {
          perror("set addr");
          return -1;
        }
      }
      else {
        fprintf(stderr, "invalid packet: %d\n", p->op);
      }
    }
  }
  return 0;
}


static int tun_alloc(char *dev, int flags) {
  struct ifreq ifr;
  int fd, err;
  char *clonedev = "/dev/net/tun";

  if( (fd = open(clonedev, O_RDWR)) < 0 ) {
     return fd;
  }

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = flags;
  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }
  if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);
  return fd;
}

int main(int argc, const char *argv[]) {

  if (argc > 1) {
    if (strcmp(argv[1], "client") == 0) {
      const char *server_addr = "34.244.251.180";
      int port = 11443;
      if (argc>2) {
        server_addr = argv[2];
      }
      if (argc>3) {
        port = atoi(argv[3]);
      }
      return novpn_client(server_addr, port);
    }
    if (strcmp(argv[1], "server") == 0) {
      int port = 11443;
      if (argc>2) {
        port = atoi(argv[2]);
      }
      return novpn_server(port, 0xc0a8ff00, 0xffffff00);
    }
  }
  
  fprintf(stderr, "novpn\n\n"
      "\t novpn server [port]\n\n"
      "\t novpn client [addr] [port]\n\n"      
      );
  return 0;
}

