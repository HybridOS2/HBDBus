/**
 * @file hbdbus.h
 * @author Vincent Wei (https://github.com/VincentWei)
 * @date 2021/01/12
 * @brief This file declares API for clients of HBDBus.
 *
 * Copyright (c) 2020~2023 FMSoft (http://www.fmsoft.cn)
 *
 * This file is part of HBDBus.
 *
 * HBDBus is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * HBDBus is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see http://www.gnu.org/licenses/.
 */

#ifndef _HBDBUS_H_
#define _HBDBUS_H_

#include <purc/purc.h>
#include "hbdbus-version.h"

/* Constants */
#define HBDBUS_PROTOCOL_NAME             "HBDBUS"
#define HBDBUS_PROTOCOL_VERSION          200
#define HBDBUS_MINIMAL_PROTOCOL_VERSION  200

#define HBDBUS_US_PATH                   "/var/tmp/hbdbus.sock"
#define HBDBUS_WS_PORT                   "7700"
#define HBDBUS_WS_PORT_RESERVED          "7701"

#define HBDBUS_PATTERN_VAR_SELF          "self"
#define HBDBUS_PATTERN_VAR_OWNER         "owner"

#define HBDBUS_PATTERN_ANY               "*"
#define HBDBUS_PATTERN_SELF              "$self"
#define HBDBUS_PATTERN_OWNER             "$owner"

#define HBDBUS_LOCALHOST                 "localhost"
#define HBDBUS_APP_HBDBUS                "cn.fmsoft.hybridos.hbdbus"
#define HBDBUS_SYS_APPS                  "cn.fmsoft.hybridos.*"
#define HBDBUS_RUNNER_DAEMON             "daemon"
#define HBDBUS_RUNNER_BUILITIN           "builtin"
#define HBDBUS_RUNNER_CMDLINE            "cmdline"

#define HBDBUS_NOT_AVAILABLE             "<N/A>"

#define HBDBUS_PUBLIC_PEM_KEY_FILE       "/etc/public-keys/public-%s.pem"
#define HBDBUS_PRIVATE_PEM_KEY_FILE      "/app/%s/private/private-%s.pem"
#define HBDBUS_PRIVATE_HMAC_KEY_FILE     "/app/%s/private/hmac-%s.key"
#define HBDBUS_LEN_PRIVATE_HMAC_KEY      64

#define HBDBUS_EC_IO                     (-1)
#define HBDBUS_EC_CLOSED                 (-2)
#define HBDBUS_EC_NOMEM                  (-3)
#define HBDBUS_EC_TOO_LARGE              (-4)
#define HBDBUS_EC_PROTOCOL               (-5)
#define HBDBUS_EC_UPPER                  (-6)
#define HBDBUS_EC_NOT_IMPLEMENTED        (-7)
#define HBDBUS_EC_INVALID_VALUE          (-8)
#define HBDBUS_EC_DUPLICATED             (-9)
#define HBDBUS_EC_TOO_SMALL_BUFF         (-10)
#define HBDBUS_EC_BAD_SYSTEM_CALL        (-11)
#define HBDBUS_EC_AUTH_FAILED            (-12)
#define HBDBUS_EC_SERVER_ERROR           (-13)
#define HBDBUS_EC_TIMEOUT                (-14)
#define HBDBUS_EC_UNKNOWN_EVENT          (-15)
#define HBDBUS_EC_UNKNOWN_RESULT         (-16)
#define HBDBUS_EC_UNKNOWN_METHOD         (-17)
#define HBDBUS_EC_UNEXPECTED             (-18)
#define HBDBUS_EC_SERVER_REFUSED         (-19)
#define HBDBUS_EC_BAD_PACKET             (-20)
#define HBDBUS_EC_BAD_CONNECTION         (-21)
#define HBDBUS_EC_CANT_LOAD              (-22)
#define HBDBUS_EC_BAD_KEY                (-23)

#define HBDBUS_LEN_HOST_NAME             PURC_LEN_HOST_NAME
#define HBDBUS_LEN_APP_NAME              PURC_LEN_APP_NAME
#define HBDBUS_LEN_RUNNER_NAME           PURC_LEN_RUNNER_NAME
#define HBDBUS_LEN_METHOD_NAME           PURC_LEN_IDENTIFIER
#define HBDBUS_LEN_BUBBLE_NAME           PURC_LEN_IDENTIFIER
#define HBDBUS_LEN_ENDPOINT_NAME         \
    (HBDBUS_LEN_HOST_NAME + HBDBUS_LEN_APP_NAME + HBDBUS_LEN_RUNNER_NAME + 3)
#define HBDBUS_LEN_UNIQUE_ID             PURC_LEN_UNIQUE_ID

#define HBDBUS_MIN_PACKET_BUFF_SIZE      512
#define HBDBUS_DEF_PACKET_BUFF_SIZE      1024
#define HBDBUS_DEF_TIME_EXPECTED         5   /* 5 seconds */

/* the maximal size of a payload in a frame (4KiB) */
#define HBDBUS_MAX_FRAME_PAYLOAD_SIZE    4096

/* the maximal size of a payload which will be held in memory (40KiB) */
#define HBDBUS_MAX_INMEM_PAYLOAD_SIZE    40960

/* the maximal time to ping client (60 seconds) */
#define HBDBUS_MAX_PING_TIME             60

/* the maximal no responding time (90 seconds) */
#define HBDBUS_MAX_NO_RESPONDING_TIME    90

/* JSON packet types */
enum {
    JPT_BAD_JSON = -1,
    JPT_UNKNOWN = 0,
    JPT_ERROR,
    JPT_AUTH,
    JPT_AUTH_PASSED,
    JPT_AUTH_FAILED,
    JPT_CALL,
    JPT_RESULT,
    JPT_RESULT_SENT,
    JPT_EVENT,
    JPT_EVENT_SENT,
};

struct _hbdbus_conn;
typedef struct _hbdbus_conn hbdbus_conn;

struct _hbdbus_pattern_list;
typedef struct _hbdbus_pattern_list hbdbus_pattern_list;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup Helpers Helper functions
 *  implemented in helpers.c, for both server and clients.
 * @{
 */

/**
 * Get the return message of a return code.
 * 
 * @param ret_code: the return code.
 *
 * Returns the pointer to the message string of the specific return code.
 *
 * Returns: a pointer to the message string.
 *
 * Since: 1.0
 */
const char *pcrdr_get_ret_message(int ret_code);

/**
 * Get the error message of an error code.
 *
 * hbdbus_get_err_message:
 * @param err_code: the error code.
 *
 * Returns the pointer to the message string of the specific error code.
 *
 * Returns: a pointer to the message string.
 *
 * Since: 1.0
 */
const char *hbdbus_get_err_message(int err_code);

/**
 * Convert an error code to a return code.
 *
 * hbdbus_errcode_to_retcode:
 * @param err_code: the internal error code of HBDBus.
 *
 * Returns the return code of the HBDBus protocol according to
 * the internal error code.
 *
 * Returns: the return code of HBDBus protocol.
 *
 * Since: 1.0
 */
int hbdbus_errcode_to_retcode(int err_code);

/**
 * Check whether a string is a valid pattern list.
 * 
 * @param pattern_list: the pointer to the wildcard pattern list such as
 * "*, com.example.?; $self, !com.foo.bar.*".
 *
 * Checks whether a wildcard pattern list string is valid. According to
 * HBDBus protocal, you can use wildcard pattern list to define
 * the access control list of a method or event.
 *
 * Returns: true for a valid wildcard pattern list, otherwise false.
 *
 * Since: 1.0
 */
bool hbdbus_is_valid_wildcard_pattern_list(const char *pattern_list);

/**
 * Sign a data.
 *
 * @param app_name: the pointer to a string contains the app name.
 * @param data: the pointer to the data will be signed.
 * @param data_len: the length of the data in bytes.
 * @param sig: the pointer to a buffer for returning
 *      the pointer to the newly allocated signature if success.
 * @param sig_len: the pointer to an unsigned integer for returning the length
 *      of the signature.
 *
 * Signs the specified data with the private key of a specific app
 * and returns the signature.
 * 
 * Note that the caller is responsible for releasing the buffer of
 * the signature.
 *
 * Returns: zero if success; an error code (<0) otherwise.
 *
 * Since: 1.0
 */
int hbdbus_sign_data(const char *app_name,
        const unsigned char *data, unsigned int data_len,
        unsigned char **sig, unsigned int *sig_len);

/**
 * Verify a signature.
 *
 * @param app_name: the pointer to a string contains the app name.
 * @param data: the pointer to the data will be verified.
 * @param data_len: the length of the data in bytes.
 * @param sig: the pointer to the signature.
 * @param sig_len: the length of the signature.
 *
 * Signs the specified data with the private key of a specific app
 * and returns the signature.
 * 
 * Note that the caller is responsible for releasing the buffer of
 * the signature.
 *
 * Returns: 1 if verified, 0 if cannot verify the signature; an error code
 * which is less than 0 means something wrong.
 *
 * Since: 1.0
 */
int hbdbus_verify_signature(const char *app_name,
        const unsigned char *data, unsigned int data_len,
        const unsigned char *sig, unsigned int sig_len);

/**
 * Parse a JSON string to a hbdbus_json object.
 *
 * hbdbus_json_packet_to_object:
 * @param json: the string contains the JSON text.
 * @param json_len: the length of the JSON text.
 * @param jo: a pointer to purc_variant_t for returning the json object.
 *
 * Parses a text packet in JSON format, returns the packet type and
 * a hbdbus_json object.
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Note that the caller is responsible for releasing the json object.
 *
 * Since: 1.0
 */
int hbdbus_json_packet_to_object(const char *json, unsigned int json_len,
        purc_variant_t *jo);

/**@}*/

/**
 * @defgroup Connection Connection functions
 *
 * The connection functions are implemented in libhbdbus.c, only for clients.
 * @{
 */

/**
 * Connect to the server via UnixSocket.
 *
 * @param path_to_socket: the path to the unix socket.
 * @param app_name: the app name.
 * @param runner_name: the runner name.
 * @param conn: the pointer to a hbdbus_conn* to return the HBDBus connection.
 *
 * Connects to a HBDBus server via WebSocket.
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Since: 1.0
 */
int hbdbus_connect_via_unix_socket(const char *path_to_socket,
        const char *app_name, const char *runner_name, hbdbus_conn** conn);

/**
 * Connect to the server via WebSocket.
 *
 * @param srv_host_name: the host name of the server.
 * @param port: the port.
 * @param app_name: the app name.
 * @param runner_name: the runner name.
 * @param conn: the pointer to a hbdbus_conn* to return the HBDBus connection.
 *
 * Connects to a HBDBus server via WebSocket.
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Note that this function is not implemented so far.
 */
int hbdbus_connect_via_web_socket(const char *srv_host_name, int port,
        const char *app_name, const char *runner_name, hbdbus_conn** conn);

/**
 * Disconnect to the server.
 *
 * @param conn: the pointer to the HBDBus connection.
 *
 * Disconnects the HBDBus connection.
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Since: 1.0
 */
int hbdbus_disconnect(hbdbus_conn* conn);

/**
 * Free a connection.
 *
 * @param conn: the pointer to the HBDBus connection.
 *
 * Frees the space used by the connection, including the connection itself.
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Since: 1.0
 */
int hbdbus_free_connection(hbdbus_conn* conn);

/**
 * The prototype of an error handler.
 *
 * @param conn: the pointer to the HBDBus connection.
 * @param jo: the json object contains the error information.
 *
 * Since: 1.0
 */
typedef void (*hbdbus_error_handler)(hbdbus_conn* conn, const purc_variant_t jo);

/**
 * hbdbus_conn_get_error_handler:
 * @param conn: the pointer to the HBDBus connection.
 *
 * Returns the current error handler of the HBDBus connection.
 *
 * Since: 1.0
 */
hbdbus_error_handler hbdbus_conn_get_error_handler(hbdbus_conn* conn);

/**
 * Set the error handler of the connection.
 *
 * @param conn: the pointer to the HBDBus connection.
 * @param error_handler: the new error handler.
 *
 * Sets the error handler of the HBDBus connection, and returns the old one.
 *
 * Since: 1.0
 */
hbdbus_error_handler hbdbus_conn_set_error_handler(hbdbus_conn* conn,
        hbdbus_error_handler error_handler);

/**
 * Get the user data associated with the connection.
 *
 * @param conn: the pointer to the HBDBus connection.
 *
 * Returns the current user data (a pointer) bound with the HBDBus connection.
 *
 * Since: 1.0
 */
void *hbdbus_conn_get_user_data(hbdbus_conn* conn);

/**
 * Set the user data associated with the connection.
 *
 * @param conn: the pointer to the HBDBus connection.
 * @param user_data: the new user data (a pointer).
 *
 * Sets the user data of the HBDBus connection, and returns the old one.
 *
 * Since: 1.0
 */
void *hbdbus_conn_set_user_data(hbdbus_conn* conn, void* user_data);

/**
 * Get the last return code from the server.
 *
 * @param conn: the pointer to the HBDBus connection.
 *
 * Returns the last return code of HBDBus result or error packet.
 *
 * Since: 1.0
 */
int hbdbus_conn_get_last_ret_code(hbdbus_conn* conn);

/**
 * Get the server host name of a connection.
 *
 * @param conn: the pointer to the HBDBus connection.
 *
 * Returns the host name of the HBDBus server.
 *
 * Since: 1.0
 */
const char *hbdbus_conn_srv_host_name(hbdbus_conn* conn);

/**
 * Get the own host name of a connection.
 *
 * @param conn: the pointer to the HBDBus connection.
 *
 * Returns the host name of the current HBDBus client.
 *
 * Since: 1.0
 */
const char *hbdbus_conn_own_host_name(hbdbus_conn* conn);

/**
 * Get the app name of a connection.
 *
 * @param conn: the pointer to the HBDBus connection.
 *
 * Returns the app name of the current HBDBus client.
 *
 * Since: 1.0
 */
const char *hbdbus_conn_app_name(hbdbus_conn* conn);

/**
 * Get the runner name of a connection.
 *
 * @param conn: the pointer to the HBDBus connection.
 *
 * Returns the runner name of the current HBDBus client.
 *
 * Since: 1.0
 */
const char *hbdbus_conn_runner_name(hbdbus_conn* conn);

/**
 * Copy the endpoint name of a connection.
 *
 * @param conn: the pointer to the HBDBus connection.
 * @param buff: the pointer to a buffer to contain the endpoint name.
 *
 * Gets the endpoint name of the HBDBus connection and
 * returns the length of the endpoint name.
 *
 * Returns: the length of the endpoint name; <= 0 means error.
 *
 * Note that the buffer should be long enough, see \a HBDBUS_LEN_ENDPOINT_NAME.
 *
 * Since: 1.0
 */
int hbdbus_conn_endpoint_name(hbdbus_conn* conn, char *buff);

/**
 * Get the endpoint name of connection (allocation version).
 *
 * @param conn: the pointer to the HBDBus connection.
 *
 * Returns a copy of the endpoint name of the HBDBus connection.
 *
 * Returns: a pointer to the string contains the endpoint name;
 *  NULL for error.
 *
 * Note that the caller is responsible for releasing the buffer.
 *
 * Since: 1.0
 */
char *hbdbus_conn_endpoint_name_alloc(hbdbus_conn* conn);

/**
 * Get the file descriptor of the connection.
 *
 * @param conn: the pointer to the HBDBus connection.
 *
 * Returns the file descriptor of the HBDBus connection socket.
 *
 * Returns: the file descriptor.
 *
 * Since: 1.0
 */
int hbdbus_conn_socket_fd(hbdbus_conn* conn);

/**
 * Get the connnection socket type.
 *
 * @param conn: the pointer to the HBDBus connection.
 *
 * Returns the socket type of the HBDBus connection.
 *
 * Returns: \a CT_UNIX_SOCKET for UnixSocket, and \a CT_WEB_SOCKET for WebSocket.
 *
 * Since: 1.0
 */
int hbdbus_conn_socket_type(hbdbus_conn* conn);

/**
 * Read a packet (allocation version).
 *
 * @param conn: the pointer to the HBDBus connection.
 * @param packet_buf: the pointer to a buffer for saving the contents of the packet.
 * @param packet_len: the pointer to a unsigned integer for returning
 *      the length of the packet.
 *
 * Reads a packet and saves the contents of the packet and returns
 * the length of the packet.
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Note that use this function only if you know the length of
 * the next packet, and have a long enough buffer to save the
 * contents of the packet.
 *
 * Also note that if the length of the packet is 0, there is no data in the packet.
 * You should ignore the packet in this case.
 *
 * Since: 1.0
 */
int hbdbus_read_packet(hbdbus_conn* conn, char *packet_buf, unsigned int *packet_len);

/**
 * Read a packet (allocation version).
 *
 * @param conn: the pointer to the HBDBus connection.
 * @param packet: the pointer to a pointer to a buffer for returning
 *      the contents of the packet.
 * @param packet_len: the pointer to a unsigned integer for returning
 *      the length of the packet.
 *
 * Reads a packet and allocates a buffer for the contents of the packet
 * and returns the contents and the length.
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Note that the caller is responsible for releasing the buffer.
 *
 * Also note that if the length of the packet is 0, there is no data in the packet.
 * You should ignore the packet in this case.
 *
 * Since: 1.0
 */
int hbdbus_read_packet_alloc(hbdbus_conn* conn, char **packet, unsigned int *packet_len);

/**
 * Send a text packet to the server.
 *
 * @param conn: the pointer to the HBDBus connection.
 * @param text: the pointer to the text to send.
 * @param txt_len: the length to send.
 *
 * Sends a text packet to the HBDBus server.
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Since: 1.0
 */
int hbdbus_send_text_packet(hbdbus_conn* conn, const char *text, unsigned int txt_len);

/**
 * Ping the server.
 *
 * @param conn: the pointer to the HBDBus connection.
 *
 * Pings the HBDBus server. The client should ping the server
 * about every 30 seconds to tell the server "I am alive".
 * According to the HBDBus protocol, the server may consider
 * a client died if there was no any data from the client
 * for 90 seconds.
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Since: 1.0
 */
int hbdbus_ping_server(hbdbus_conn* conn);

/**
 * The prototype of a method handler.
 *
 * @param conn: the pointer to the HBDBus connection.
 * @param from_endpoint: the endpoint name emited the call.
 * @param to_method: the method name of the call.
 * @param method_param: the method parameter (a string).
 * @param err_code: the pointer to an integer for the error code.
 *
 * Returns: the return value (a string) if \a err_code contains 0.
 *
 * Since: 1.0
 */
typedef char *(*hbdbus_method_handler)(hbdbus_conn* conn,
        const char *from_endpoint, const char *to_method,
        const char *method_param, int *err_code);

/**
 * Register a procedure.
 *
 * @param conn: the pointer to the HBDBus connection.
 * @param method_name: the method name of the procedure.
 * @param for_host: the pattern list for allowed hosts.
 * @param for_app: the pattern list for allowed apps.
 * @param method_handler: the local method handler for this procedure.
 *
 * Registers an procedure to the HBDBus server.
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Since: 1.0
 */
int hbdbus_register_procedure(hbdbus_conn* conn, const char *method_name,
        const char *for_host, const char *for_app,
        hbdbus_method_handler method_handler);

/**
 * The prototype of a method handler (const version).
 *
 * @param conn: the pointer to the HBDBus connection.
 * @param from_endpoint: the endpoint name emited the call.
 * @param to_method: the method name of the call.
 * @param method_param: the method parameter (a string).
 * @param err_code: the pointer to an integer for the error code.
 *
 * Returns: the return value (a const string) if \a err_code contains 0.
 *
 * Since: 1.0
 */
typedef const char *(*hbdbus_method_handler_const)(hbdbus_conn* conn,
        const char *from_endpoint, const char *to_method,
        const char *method_param, int *err_code);

/**
 * Register a procedure with a const method handler.
 *
 * @param conn: the pointer to the HBDBus connection.
 * @param method_name: the method name of the procedure.
 * @param for_host: the pattern list for allowed hosts.
 * @param for_app: the pattern list for allowed apps.
 * @param method_handler: the local method handler (const version)
 *  for this procedure.
 *
 * Registers an procedure to the HBDBus server.
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Since: 1.0
 */
int hbdbus_register_procedure_const(hbdbus_conn* conn, const char *method_name,
        const char *for_host, const char *for_app,
        hbdbus_method_handler_const method_handler);

/**
 * Revoke a registered procedure.
 *
 * @param conn: the pointer to the HBDBus connection.
 * @param method_name: the method name of the procedure.
 *
 * Revokes an procedure from the HBDBus server.
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Since: 1.0
 */
int hbdbus_revoke_procedure(hbdbus_conn* conn, const char *method_name);

/**
 * Register an event.
 *
 * @param conn: the pointer to the HBDBus connection.
 * @param bubble_name: the bubble name of the event.
 * @param for_host: the pattern list for allowed hosts.
 * @param for_app: the pattern list for allowed apps.
 *
 * Registers an event to the HBDBus server.
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Since: 1.0
 */
int hbdbus_register_event(hbdbus_conn* conn, const char *bubble_name,
        const char *for_host, const char *for_app);

/**
 * Revoke a registered event.
 *
 * @param conn: the pointer to the HBDBus connection.
 * @param bubble_name: the bubble name of the event.
 *
 * Revokes an event from the HBDBus server.
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Since: 1.0
 */
int hbdbus_revoke_event(hbdbus_conn* conn, const char *bubble_name);

/**
 * Fire an event.
 *
 * @param conn: the pointer to the HBDBus connection.
 * @param bubble_name: the bubble name of the event.
 * @param bubble_data: the bubble data (a string) of the event.
 *
 * Fires an event for the specified bubble name.
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Since: 1.0
 */
int hbdbus_fire_event(hbdbus_conn* conn,
        const char *bubble_name, const char *bubble_data);

/**
 * The prototype of an event handler.
 *
 * @param conn: the pointer to the HBDBus connection.
 * @param from_endpoint: the endpoint name of the event.
 * @param from_bubble: the bubble name of the event.
 * @param bubble_data: the bubble data (a string) of the event.
 *
 * Since: 1.0
 */
typedef void (*hbdbus_event_handler)(hbdbus_conn* conn,
        const char *from_endpoint, const char *from_bubble,
        const char *bubble_data);

/**
 * Subscribe an event.
 *
 * @param conn: the pointer to the HBDBus connection.
 * @param endpoint: the endpoint name of the event.
 * @param bubble_name: the bubble name of the event.
 * @param event_handler: the event handler.
 *
 * This function subscribes the specified event. When
 * there is an event, \a event_handler will be called with
 * the bubble data.
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Since: 1.0
 */
int hbdbus_subscribe_event(hbdbus_conn* conn,
        const char *endpoint, const char *bubble_name,
        hbdbus_event_handler event_handler);

/**
 * Unsubscribe an event.
 *
 * @param conn: the pointer to the HBDBus connection.
 * @param endpoint: the endpoint name of the event.
 * @param bubble_name: the bubble name of the event.
 *
 * This function unsubscribes the specified event.
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Since: 1.0
 */
int hbdbus_unsubscribe_event(hbdbus_conn* conn,
        const char *endpoint, const char *bubble_name);

/**
 * The prototype of a result handler.
 *
 * @param conn: the pointer to the HBDBus connection.
 * @param from_endpoint: the endpoint name of the result.
 * @param from_method: the method name of the result.
 * @param call_id: the call identifier.
 * @param ret_code: the return code of the result.
 * @param ret_value: the return value (a string) of the result.
 *
 * Returns: 0 for finished the handle of the result; otherwise -1.
 *
 * Since: 1.0
 */
typedef int (*hbdbus_result_handler)(hbdbus_conn* conn,
        const char *from_endpoint, const char *from_method,
        const char *call_id,
        int ret_code, const char *ret_value);

/**
 * Call a procedure and handle the result in a callback handler.
 *
 * @param conn: the pointer to the HBDBus connection.
 * @param endpoint: the endpoint name of the procedure.
 * @param method: the method of the procedure.
 * @param method_param: the parameter of the method.
 * @param time_expected: the expected return time in seconds.
 * @param result_handler: the result handler.
 * @param call_id (nullable): the buffer to store the call identifier.
 *
 * This function emits a call to a remote procedure and
 * returns immediately. The result handler will be called
 * in subsequent calls of \a hbdbus_read_and_dispatch_packet().
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Since: 1.0
 */
int hbdbus_call_procedure(hbdbus_conn* conn,
        const char *endpoint,
        const char *method, const char *method_param,
        int time_expected, hbdbus_result_handler result_handler,
        const char **call_id);

/**
 * Call a procedure and wait the result.
 *
 * @param conn: the pointer to the HBDBus connection.
 * @param endpoint: the endpoint name of the procedure.
 * @param method_name: the method of the procedure.
 * @param method_param: the parameter of the method.
 * @param time_expected: the expected return time in seconds.
 * @param ret_code: the pointer to an integer to return the return code
 *      of the result.
 * @param ret_value: the pointer to a pointer to return the value (a string)
 *      of the result.
 *
 * This function calls a remote procedure and wait for the result.
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Since: 1.0
 */
int hbdbus_call_procedure_and_wait(hbdbus_conn* conn, const char *endpoint,
        const char *method_name, const char *method_param,
        int time_expected, int *ret_code, char** ret_value);

/**
 * Read and dispatch the packet from the server.
 *
 * @param conn: the pointer to the HBDBus connection.
 *
 * This function read a HBDBus packet and dispatches the packet to
 * a event handler, method handler, or result handler.
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Since: 1.0
 */
int hbdbus_read_and_dispatch_packet(hbdbus_conn* conn);

/**
 * Wait and dispatch the packet from the server.
 *
 * @param conn: the pointer to the HBDBus connection.
 * @param timeout_ms (not nullable): the timeout value in milliseconds.
 *
 * This function waits for a HBDBus packet by calling select()
 * and dispatches the packet to event handlers, method handlers,
 * or result handlers.
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Note that if you need watching multiple file descriptors, you'd
 * better user \a hbdbus_read_and_dispatch_packet.
 *
 * Since: 1.0
 */
int hbdbus_wait_and_dispatch_packet(hbdbus_conn* conn, int timeout_ms);

/**@}*/

#ifdef __cplusplus
}
#endif

/**
 * @addtogroup Helpers
 *  @{
 */

/**
 * Check whether a string is a valid method name.
 *
 * @param method_name: the pointer to the method name string.
 *
 * Checks whether a method name is valid. According to HBDBus protocal,
 * the method name should be a valid token and not longer than
 * \a HBDBUS_LEN_METHOD_NAME.
 *
 * Note that a string with a length longer than \a HBDBUS_LEN_METHOD_NAME will
 * be considered as an invalid method name.
 *
 * Returns: true for a valid token, otherwise false.
 *
 * Since: 1.0
 */
static inline bool
hbdbus_is_valid_method_name(const char *method_name)
{
    return purc_is_valid_token(method_name, HBDBUS_LEN_METHOD_NAME);
}

/**
 * Check whether a string is a valid bubble name.
 *
 * @param bubble_name: the pointer to the bubble name string.
 *
 * Checks whether a bubble name is valid. According to HBDBus protocal,
 * the bubble name should be a valid token and not longer than
 * \a HBDBUS_LEN_BUBBLE_NAME.
 *
 * Note that a string with a length longer than \a HBDBUS_LEN_BUBBLE_NAME will
 * be considered as an invalid bubble name.
 *
 * Returns: true for a valid token, otherwise false.
 *
 * Since: 1.0
 */
static inline bool
hbdbus_is_valid_bubble_name(const char *bubble_name)
{
    return purc_is_valid_token(bubble_name, HBDBUS_LEN_BUBBLE_NAME);
}

/**@}*/

#endif /* !_HBDBUS_H_ */

