# Socket API Test Suite

Socket API Test Suite checks the socket API functions against the native OS behaviour.

TE is used as an Engine that allows to prepare desired environment for every test. This guarantees reproducible test results.

Sapi TS API allow to test the following functions:
* socket() / bind() / listen() / connect()
* accept()/accept4()
* read() / recv() / recvfrom() / recvmsg() / recvmmsg()
* write() / send() / sendto() / sendmsg() / sendmmsg()
* select() / pselect() / poll() / ppoll()
* epoll_create() / epoll_ctl() / epoll_wait() / epoll_pwait()
* getpeername() / getsockname()
* ioctl()
* getsockopts() / setsockopts()
* close()
* and others

This API allows to call these functions, get their output, analyze it and check for expected behaviour in different situations.

## Licence
See license in the LICENSE file.
