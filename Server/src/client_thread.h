/*
 * client_thread.h
 *
 *  Created on: Aug 26, 2014
 *      Author: tievens
 */

#ifndef CLIENT_THREAD_H_
#define CLIENT_THREAD_H_

#include "DbImpl_mysql.h"
#include "BMPListener.h"
#include "Logger.h"
#include "Config.h"

struct ThreadMgmt {
    pthread_t thr;
    BMPListener::ClientInfo client;
    Cfg_Options *cfg;
    Logger *log;
    bool running;                       // true if running, zero if not running
};

struct ClientThreadInfo {
    mysqlBMP *mysql;
    BMPListener::ClientInfo *client;
    Logger *log;
};

/**
 * Client thread function
 *
 * Thread function that is called when starting a new thread.
 * The DB/mysql is initialized for each thread.
 *
 * @param [in]  arg     Pointer to the BMPServer ClientInfo
 */
void *ClientThread(void *arg);



#endif /* CLIENT_THREAD_H_ */
