/*--------------------------------------------------------------------------------------------------
------------------------------------------ Description ---------------------------------------------
--------------------------------------------------------------------------------------------------*/
//
// version: 1.0 4Apr23
//
// The following code is the firmware for the Cooja mote to function as a client. The client has the
// following functionality:
// * Calculates the PUF key based on a pseudorandom unix machine.
// * Initializes the connection with the sync mote
// * Sends the message "PUFKey hello <id>" to the sync mote
// * Receives a reply from the sync mote
// * At a random timeframe the sync mote sends back the message "validate", the client mote then
//   calculates the PUF key again and replies to the sync mote. More specifically in the case of the
//   client the PUF key will remain the same because it is a pseudorandom key, and we do not want to
//   change it.
// * Additionally, each time the mote receives a new message from another mote it saves the
//   IP, Port, Key of the sender in arrays. Each time there is a new message it searches in the
//   arrays to verify if the mote had sent a message in the past. If mote had sent a message in the
//   past and the key is matching then the message is received. Otherwise, the mote closes the
//   connection.
// * Finally, the mote after some random time performs the same actions again.

/*--------------------------------------------------------------------------------------------------
------------------------------------- Imports of the libraries -------------------------------------
--------------------------------------------------------------------------------------------------*/

#include "contiki.h"
#include "net/routing/routing.h"
#include "random.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include <stdint.h>
#include <inttypes.h>
#include "sys/log.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

/*--------------------------------------------------------------------------------------------------
------------------------------------------ Initialize ----------------------------------------------
--------------------------------------------------------------------------------------------------*/

// Initialize the parameters for the logging module
#define LOG_MODULE "Client"
#define LOG_LEVEL LOG_LEVEL_INFO

// Initialize the network parameters
#define WITH_SERVER_REPLY  1
#define UDP_CLIENT_PORT	8765
#define UDP_SERVER_PORT	5678

// Initialize the time interval for the etimer module
#define SEND_INTERVAL		  (60 * CLOCK_SECOND)

// Initialize the name of the node and the mode of the node
const char name[]="UDP Client";
const bool server = false;

/*--------------------------------------------------------------------------------------------------
------------------------------------ Initialize the PUF Key ----------------------------------------
--------------------------------------------------------------------------------------------------*/

// Initialize the PUF key
char local_client_key[20] = "initialkey";

// Initialize the parameters for the validation
bool initialSetupPUF=true;
bool validate = false;

/*--------------------------------------------------------------------------------------------------
---------------------------------- Initialize arrays for the nodes ---------------------------------
--------------------------------------------------------------------------------------------------*/

// Initialize the maximum nodes
#define MAX_NODES 10

// Initialize the remote keys array
char remotekeys[MAX_NODES][20];

// Initialize the sender port array
uint16_t sender_ports[MAX_NODES];

// Initialize the IP array
uip_ipaddr_t sender_addrs[MAX_NODES];

// Initialize the zero IPv6 address
const uip_ipaddr_t uip_all_zeroes_addr;

/*--------------------------------------------------------------------------------------------------
-------------------------------------------- UDP Client --------------------------------------------
--------------------------------------------------------------------------------------------------*/

// Create the static instance of the UDP connection
static struct simple_udp_connection udp_conn;

// Initialize the rx counter
static uint32_t rx_count = 0;

// Create the UDP Client process and start it
PROCESS(udp_client_process, name);
AUTOSTART_PROCESSES(&udp_client_process);

// Call back function. This function is used to process the received messages from the UDP client
static void
udp_rx_callback(struct simple_udp_connection *c,
                const uip_ipaddr_t *sender_addr,
                uint16_t sender_port,
                const uip_ipaddr_t *receiver_addr,
                uint16_t receiver_port,
                const uint8_t *data,
                uint16_t datalen)
{
  // The following code block gets the key from the message
  char data_copy[121];
  memcpy(data_copy, data, datalen);
  data_copy[121] = '\0';
  char *token = strtok(data_copy, " ");
  char remotekey[20];
  if (token != NULL) {
    strcpy(remotekey, token);
  }
  // The following code block gets the message, and validates if there is a validation message send
  char *taken = strtok(NULL, " ");
  LOG_INFO("Received message '%s'\n",taken);
  if (taken != NULL && strcmp(taken, "validate") == 0) {
    LOG_INFO("Received validation message\n");
    validate=true;
  }

  // The following code block performs the validation of the KEY received and the IP of the sender
  int i;
  for (i = 0; i < MAX_NODES; i++) {
    // Get the IP of the sender
    uip_ipaddr_t* ip_ptr = &sender_addrs[i];
    // Perform a validation if the sender IP and port already exist in the aforementioned arrays
    if (sender_ports[i] == sender_port && memcmp(ip_ptr, sender_addr, sizeof(uip_ip6addr_t)) == 0){
      // Verify if the remote key is validated or not
      if (strcmp(remotekeys[i], remotekey) == 0){
        // Key is validated
        LOG_INFO("The key '%s' of the node with Port:'%u' ",remotekey,sender_port);
        LOG_INFO_("IP: '");
        LOG_INFO_6ADDR(sender_addr);
        LOG_INFO_("' is verified.\n");
        break;
      }
      else{
        // Key is not validated
        LOG_INFO("The key '%s' of the node with Port:'%u' ",remotekey,sender_port);
        LOG_INFO_("IP: '");
        LOG_INFO_6ADDR(sender_addr);
        LOG_INFO_("' is not verified closing the communication with this node.\n");
        // Drop the connection with no further processing
        return;
        break;
      }
  }
  else{
    // In this case the node has sent a message for the first time, saving in the arrays the IP, port
    // and the key of the node. The values are stored in an empty cell in the arrays
    if (sender_ports[i] == 0 && uip_ipaddr_cmp(&sender_addrs[i], &uip_all_zeroes_addr)) {
      strcpy(remotekeys[i], token);
      sender_ports[i] = sender_port;
      uip_ipaddr_copy(&sender_addrs[i], sender_addr);
      LOG_INFO("The mote with:key '%s' ,Port:'%u' ",remotekey,sender_port);
      LOG_INFO_(",IP: '");
      LOG_INFO_6ADDR(sender_addr);
      LOG_INFO_("' was added to the list of known mote.\n");
      break;
     }
    }
  }

  // Validation code block, in case the Server sends a validate message this node will keep its
  // original PUF key. Since the code is working with a random generator instead of a real PUF
  //We need to keep the key the same.
  if(validate){
    LOG_INFO("The key remains for the client '%s' the same\n",local_client_key);
    validate=false;
  }

  // Print in the logs the request received and the details of the sender
  LOG_INFO("%s: Received request '%.*s' from mote with: Port:'%u' key:'%s' ", name, datalen, (char*) data,sender_port, remotekey);
  LOG_INFO_("IP: '");
  LOG_INFO_6ADDR(sender_addr);
  LOG_INFO_("'\n");

#if LLSEC802154_CONF_ENABLED
  LOG_INFO_(" LLSEC LV:%d", uipbuf_get_attr(UIPBUF_ATTR_LLSEC_LEVEL));
#endif
  rx_count++;
}

/*--------------------------------------------------------------------------------------------------
---------------------------------- Main process of the client node -----------------------------------
--------------------------------------------------------------------------------------------------*/

PROCESS_THREAD(udp_client_process, ev, data){
  // Create the instance of the timer
  static struct etimer periodic_timer;

  // Set the message length
  static char str[120];

  // Set the ip of the destination
  uip_ipaddr_t dest_ipaddr;

  // Set the tx counter and the missed tx counter
  static uint32_t tx_count;
  static uint32_t missed_tx_count;

  // Start the main process
  PROCESS_BEGIN();

  // Produce the PUF key
  if(initialSetupPUF){
    // The key is used using urandom pseudorandom unix machine and it is saved in the variable
    // local_client_key
    int urandom_fd = open("/dev/urandom", O_RDONLY);
    unsigned int seed_value;
    read(urandom_fd, &seed_value, sizeof(seed_value));
    close(urandom_fd);
    srand(seed_value);
    for(int i = 0; i < 10; i++) {
      local_client_key[i] = rand() % 26 + 'a';
    }
    local_client_key[10] = '\0'; // terminate the string of the key
    LOG_INFO("The PUF key of the client is: '%s'\n", local_client_key);
    initialSetupPUF=false;
  }

  // Initialize UDP connection
  simple_udp_register(&udp_conn, UDP_CLIENT_PORT, NULL, UDP_SERVER_PORT, udp_rx_callback);

  // Set the timer
  etimer_set(&periodic_timer, random_rand() % SEND_INTERVAL);
  while(1) {
    // Wait until the timer expires
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));

    if(NETSTACK_ROUTING.node_is_reachable() &&
        NETSTACK_ROUTING.get_root_ipaddr(&dest_ipaddr)) {

      // Print statistics every 10th TX
      if(tx_count % 10 == 0) {
        LOG_INFO("Tx/Rx/MissedTx: %" PRIu32 "/%" PRIu32 "/%" PRIu32 "\n",
                 tx_count, rx_count, missed_tx_count);
      }

      // Print the message in the log that will be sent to the other motes
      LOG_INFO("Sending request %"PRIu32" with key: %s to ", tx_count, local_client_key);
      LOG_INFO_6ADDR(&dest_ipaddr);
      LOG_INFO_("\n");

      // Prepare the message for sending
      snprintf(str, sizeof(str), "%s hello %" PRIu32 "", local_client_key, tx_count);

      // Send the message
      simple_udp_sendto(&udp_conn, str, strlen(str), &dest_ipaddr);

      // Increase the tx counter
      tx_count++;
    }
    else {
      LOG_INFO("Not reachable yet\n");
      if(tx_count > 0) {
        missed_tx_count++;
      }
    }

    // Add some jitter
    etimer_set(&periodic_timer, SEND_INTERVAL
      - CLOCK_SECOND + (random_rand() % (2 * CLOCK_SECOND)));
  }

  PROCESS_END();
}
/*------------------------------------------------------------------------------------------------*/
