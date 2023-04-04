/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */
/*--------------------------------------------------------------------------------------------------
------------------------------------------ Description ---------------------------------------------
--------------------------------------------------------------------------------------------------*/
//
// version: 1.0 4Apr23
//
// The following code is the firmware for the Cooja mote to function as a server. The server has the
// following functionality:
// * Calculates the PUF key based on a pseudorandom unix machine.
// * Starts the connection and waits for messages from the clients
// * Each time the mote receives a new message from another mote it saves the
//   IP, Port, Key of the sender in arrays. Each time there is a new message it searches in the
//   arrays to verify if the mote had sent a message in the past. If mote had sent a message in the
//   past and the key is matching then the message is received and replies with the same
//   message using his key. Otherwise, the mote closes the connection.
// * At a random time frame it sends a validation message to the other nodes, then the nodes
//   Calculate their PUF and respond.
// * Additionally, if the server receives a validation message, then it calculates his PUF Key and
//   replies back.

/*--------------------------------------------------------------------------------------------------
------------------------------------- Imports of the libraries -------------------------------------
--------------------------------------------------------------------------------------------------*/

#include "contiki.h"
#include "net/routing/routing.h"
#include "random.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "net/ipv6/uip.h"
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
#define LOG_MODULE "Server"
#define LOG_LEVEL LOG_LEVEL_INFO

// Initialize the network parameters
#define WITH_SERVER_REPLY  1
#define UDP_CLIENT_PORT	8765
#define UDP_SERVER_PORT	5678

// Initialize the name of the node and the mode of the node
const char name[]="UDP server";
const bool server = true;

/*--------------------------------------------------------------------------------------------------
------------------------------------ Initialize the PUF Key ----------------------------------------
--------------------------------------------------------------------------------------------------*/

// Initialize the PUF key
char local_server_key[20] = "initialkey";

// Initialize the parameters for the validation
bool initialSetupPUF=true;
bool validate = false;
bool servervalidate = false;

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
-------------------------------------------- UDP Server --------------------------------------------
--------------------------------------------------------------------------------------------------*/

// Create the static instance of the UDP connection
static struct simple_udp_connection udp_conn;

// Create the UDP Server process and start it
PROCESS(udp_server_process, name);
AUTOSTART_PROCESSES(&udp_server_process);

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
  static char str[120];
  char data_copy[121];
  memcpy(data_copy, data, datalen);
  data_copy[121] = '\0';
  char *token = strtok(data_copy, " ");
  char remotekey[20];
  if (token != NULL) {
    strcpy(remotekey, token);
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

  // The following code block gets the message, and validates if there is a validation message send
  char *taken = strtok(NULL, " ");
  LOG_INFO("Received message '%s'\n",taken);
  if (taken != NULL && strcmp(taken, "validate") == 0) {
    LOG_INFO("Received validation message\n");
    servervalidate=true;
  }

  // Validation code block, in case the server receives a validate message this node will keep its
  // original PUF key. Since the code is working with a random generator instead of a real PUF
  // We need to keep the key the same.
  if(servervalidate){
    LOG_INFO("The key remains for the server '%s' the same\n",local_server_key);
    servervalidate=false;
  }

  // Print in the logs the request received and the details of the sender
  LOG_INFO("%s: Received request '%.*s' from mote with: Port:'%u' key:'%s' ", name, datalen, (char*) data,sender_port, remotekey);
  LOG_INFO_("IP: '");
  LOG_INFO_6ADDR(sender_addr);
  LOG_INFO_("'\n");

#if WITH_SERVER_REPLY

  // Send validation message
  if(validate) {
    int i;
    for (i = 0; i < MAX_NODES; i++) {
      uip_ipaddr_t* valid_ip_pt = &sender_addrs[i];
      char valid_remotekey[20];
      strcpy(valid_remotekey,remotekeys[i]);
      // Check if both sender_addrs[i] and remotekeys[i] are populated
      if (valid_ip_pt && valid_remotekey[0] != '\0') {
        LOG_INFO("Sending request to validate, to the node with IP: '");
        LOG_INFO_6ADDR(valid_ip_pt);
        LOG_INFO_("', Key: '%s'\n",valid_remotekey);
        snprintf(str, sizeof(str), "%s validate ", local_server_key);
        simple_udp_sendto(&udp_conn, str, strlen(str), valid_ip_pt);
      }
    }
    validate = false;
  }

  // send back the same string to the client as an echo reply
  LOG_INFO("Sending response from the '%s' with key '%s'.\n",name,local_server_key);

  //Preparing the reply with the server key:
  char new_data[121];
  char new_data_copy[121];
  memcpy(new_data_copy, data, datalen);
  sprintf(new_data, "%s %s", local_server_key, new_data_copy + strlen(remotekey) + 1);
  size_t new_data_len = strlen(new_data);
  simple_udp_sendto(&udp_conn, new_data, new_data_len, sender_addr);

#endif /* WITH_SERVER_REPLY */
}

/*--------------------------------------------------------------------------------------------------
---------------------------------- Main process of the root node -----------------------------------
--------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(udp_server_process, ev, data){
  // Create the instance of the timer
  static struct etimer et;

  // Start the main process
  PROCESS_BEGIN();

  // Initialize DAG root
  NETSTACK_ROUTING.root_start();

  // Print the functionality of the process
  LOG_INFO("The mode of the node is set to: '%s'\n", name);

  // Produce the PUF key
  if(initialSetupPUF){
    // The key is used using urandom pseudorandom unix machine and it is saved in the variable
    // local_server_key
    int urandom_fd = open("/dev/urandom", O_RDONLY);
    unsigned int seed_value;
    read(urandom_fd, &seed_value, sizeof(seed_value));
    close(urandom_fd);
    srand(seed_value);
    for(int i = 0; i < 10; i++) {
      local_server_key[i] = rand() % 26 + 'a';
    }
    local_server_key[10] = '\0'; // terminate the string
    LOG_INFO("The PUF key of the client is: '%s'\n", local_server_key);
    initialSetupPUF=false;
  }

  // Initialize UDP connection
  simple_udp_register(&udp_conn, UDP_SERVER_PORT, NULL, UDP_CLIENT_PORT, udp_rx_callback);

  // At a random time frame to send a validation message to the nodes
  etimer_set(&et, random_rand() % CLOCK_SECOND * 320);
  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
      validate=true;
      etimer_set(&et, random_rand() % CLOCK_SECOND * 180);
    }



  PROCESS_END();
}
/*------------------------------------------------------------------------------------------------*/

