// Usage:
// $ ./pop3_client [host] [username] [password]

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUF_SIZE 4096
#define CLIENT_PORT 1234
#define SERVER_PORT 110
#define SSL_PORT  "995"
#define INFO_FILE "Info.txt"

int establish_connection (int*, char*, char*, char*);
int transact (int s, char* mes);
int ssl_transact(BIO* bio, char* mes);
BIO  *SSL_INITIALIZE(char *, char*, char*);

int main (int argc, char** argv) {
  char host[BUF_SIZE];
  char user[BUF_SIZE];
  char pass[BUF_SIZE];
  char cryp[BUF_SIZE];
  bool bcrypt;
  switch (argc) {
    case 1:
      fprintf (stderr, "host: ");
      fscanf (stdin, "%s", &host[0]);
      fprintf (stderr, "crypt: ");
      fscanf (stdin, "%s", &cryp[0]);
      fprintf (stderr, "user: ");
      fscanf (stdin, "%s", &user[0]);
      fprintf (stderr, "pass: ");
      fscanf (stdin, "%s", &pass[0]);
      break;
    case 2:
      strcpy (host, argv[1]);
      fprintf (stderr, "crypt: ");
      fscanf (stdin, "%s", &cryp[0]);
      fprintf (stderr, "user: ");
      fscanf (stdin, "%s", &user[0]);
      fprintf (stderr, "pass: ");
      fscanf (stdin, "%s", &pass[0]);
      break;
    case 3:
      strcpy (host, argv[1]);
      strcpy (cryp, argv[2]);
      fprintf (stderr, "user: ");
      fscanf (stdin, "%s", &user[0]);
      fprintf (stderr, "pass: ");
      fscanf (stdin, "%s", &pass[0]);
      break;
    case 4:
      strcpy (host, argv[1]);
      strcpy (cryp, argv[2]);
      strcpy (user, argv[3]);
      fprintf (stderr, "pass: ");
      fscanf (stdin, "%s", &pass[0]);
      break;
    case 5:
      strcpy (host, argv[1]);
      strcpy (cryp, argv[2]);
      strcpy (user, argv[3]);
      strcpy (pass, argv[4]);
      break;
    default:
      fprintf (stderr, "Incorrect number of arguments.\n");
      exit(1);
      break;
  }

  if(strncmp(cryp,"ssl", 3)) bcrypt = 0;
  else if(strncmp(cryp, "none",4)) bcrypt = 1;

  fprintf (stderr, "\nUsing\n\thost: %s\n\tcrypt: %s\n\tuser: %s\n\tpass: %s\n\n", host, cryp, user, pass);

  int sock;
  BIO *bio;

  if(bcrypt) {
    bio = SSL_INITIALIZE(host, user, pass);
    if (!bio) exit(0);
  } else {
    establish_connection (&sock, host, user, pass);
  }

  char buf[BUF_SIZE];
  int len;

  while (1) {
    len = 0;
    fprintf(stderr, "> ");
    std::cin.getline (buf, BUF_SIZE);
    len = strlen(buf);
    buf[len] = '\n';
    buf[len+1] = '\0';
    if (strlen(buf) > 1) {
      if(bcrypt)  ssl_transact(bio, buf);
      else     transact (sock, buf);
      if(!strcmp(buf, "QUIT\n")) {
        if(bcrypt)  close (sock);
        else BIO_free_all(bio);
        exit(0);
      }
    }
  }
}

int establish_connection (int* s, char* h, char* u, char* p) {
  int rez;
  char buf[BUF_SIZE];

  struct hostent *hp;
  struct sockaddr_in clnt_sin;
  struct sockaddr_in srv_sin;

  *s = socket(AF_INET, SOCK_STREAM, 0);
  memset ((char *)&clnt_sin, '\0', sizeof(clnt_sin));
  clnt_sin.sin_family = AF_INET;
  clnt_sin.sin_addr.s_addr = INADDR_ANY;
  clnt_sin.sin_port = CLIENT_PORT;
  bind (*s, (struct sockaddr *)&clnt_sin, sizeof(clnt_sin));
  memset ((char *)&srv_sin, '\0', sizeof(srv_sin));
  srv_sin.sin_family = AF_INET;
  hp = gethostbyname (h);
  memcpy ((char *)&srv_sin.sin_addr, hp->h_addr, hp->h_length);
  srv_sin.sin_port = htons(SERVER_PORT);

  fprintf (stderr, "Connecting to \'%s\'\n", h);

  rez = connect (*s, (struct sockaddr *)&srv_sin, sizeof(srv_sin));
  fprintf (stderr, "%d: %s\n", rez, strerror(errno));

  rez = recv (*s, buf, BUF_SIZE, 0);
  buf[rez+1] = '\0';
  fprintf (stderr, "< %s\n", buf);

  sprintf (buf, "USER %s\n", u);
  fprintf (stderr, "> %s", buf);
  transact (*s, buf);
  sprintf (buf, "PASS %s\n", p);
  fprintf (stderr, "> %s", buf);
  transact (*s, buf);
}


BIO  *SSL_INITIALIZE(char *host, char* user, char* pass) {
    BIO * bio;
    SSL * ssl;
    SSL_CTX * ctx;
    int nRet, sock;
    fd_set connfds;
    struct timeval timeout;
    char buf[BUF_SIZE];
    char host_port[BUF_SIZE];
    host_port[0]='\0';
    strcat(host_port,host);
    strcat(host_port,":");
    strcat(host_port,SSL_PORT);
    int rez;

    SSL_library_init();
    ERR_load_BIO_strings();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    ctx = SSL_CTX_new(SSLv23_client_method());
    bio = BIO_new_ssl_connect(ctx);
    BIO_get_ssl(bio, & ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
  	BIO_get_fd(bio, &sock);

    fprintf (stderr, "SSL connecting to \'%s\'\n", host_port);

    BIO_set_conn_hostname(bio, host_port);
    if((nRet = BIO_do_connect(bio)) <= 0) {
        fprintf(stderr, "Error attempting to connect\n");
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return NULL;
    }

    BIO_read(bio, buf, BUF_SIZE);
    fprintf (stderr, "> %s", buf);

    buf[0] = '\0';
    strcat(buf,"NOOP\n");
  fprintf (stderr, "< %s", buf);
    rez = ssl_transact(bio, buf);

  if(strncmp(buf,"+OK",3)){
    sprintf (buf, "USER %s\n", user);
    fprintf (stderr, "< %s", buf);
    ssl_transact (bio, buf);
    sprintf (buf, "PASS %s\n", pass);
    fprintf (stderr, "< %s", buf);
    ssl_transact (bio, buf);
    return bio;
  }
  else{
        fprintf(stderr, "Error SSL connection\n");
        return NULL;
  }

}

// 0 - success ('+OK'-starting line recieved)
// 1 - fail (else case)
// But is not checked anywhere...
int transact (int s, char* mes)
{
  int recv_len,n=0;
  char buf[BUF_SIZE];
  strcpy (buf, mes);

  send (s, buf, strlen(buf), 0);

  fprintf (stderr, "------>%d: %s", (int)strlen(buf), buf);

  if(!strncmp(buf,"NOOP", 4) || !strncmp(buf,"USER", 4) || !strncmp(buf,"PASS", 4)|| !strncmp(buf,"STAT", 4) || !strncmp(buf, "DELE", 4)){
    n += recv_len = recv (s, buf, BUF_SIZE, 0);
  } else {
    while(buf[recv_len-3]!='.'){
      recv_len = recv (s, buf, BUF_SIZE, 0);
      buf[recv_len]='\0';
      fprintf (stderr, "%s",buf);
    }
  }
  buf[n] = '\0';

  if (!strncmp (buf, "+OK", 3))
    return 0;
  else
    return recv_len;
}

int ssl_transact(BIO* bio, char* mes){
  int recv_len,n=0;
  char buf[BUF_SIZE];
  strcpy (buf, mes);

  BIO_write (bio, buf, strlen(buf));
  buf[0]='\0';

  fprintf (stderr, "> ");
  recv_len = BIO_read (bio, buf, BUF_SIZE);

  buf[recv_len]='\0';
  fprintf (stderr, "%s", buf);

}
