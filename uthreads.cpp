//
// Created by cheziunix on 25/04/2021.
//
#include <iostream>
#include "uthreads.h"
#include <queue>
#include <deque>
#include <functional>
#include <vector>
#include <unordered_set>
#include <csetjmp>
#include <csignal>
#include <sys/time.h>
#define MAIN_TRD 0


#ifdef __x86_64__
/* code for 64 bit Intel arch */

typedef unsigned long address_t;
#define JB_SP 6
#define JB_PC 7

/*
 * A translation is required when using an address of a variable.
*/
address_t translate_address(address_t addr)
{
address_t ret;
asm volatile("xor    %%fs:0x30,%0\n"
"rol    $0x11,%0\n"
: "=g" (ret)
: "0" (addr));
return ret;
}

#else
/* code for 32 bit Intel arch */

typedef unsigned int address_t;
#define JB_SP 4
#define JB_PC 5

/* A translation is required when using an address of a variable.
   Use this as a black box in your code. */
address_t translate_address(address_t addr)
{
address_t ret;
asm volatile("xor    %%gs:0x18,%0\n"
"rol    $0x9,%0\n"
: "=g" (ret)
: "0" (addr));
return ret;
}


#endif
using std::cerr;
using std::vector;
using std::greater;
using std::priority_queue;
using std::string;
using std::nothrow;
using std::endl;


typedef struct thread thread;

static priority_queue<unsigned int, vector<unsigned int>, greater<int>> min_tid;

static thread *thread_party[MAX_THREAD_NUM];

static int blocked_threads_num = 0;

static std::deque<thread*> ready_list;

static struct itimerval timer;

static sigset_t blocked_sigs;

static struct sigaction sa;

static int total_quantum;

static int running_trd;

static int threads_num;

static int mutex;



struct thread
{
    int tid{};
    char *stack{};
    bool blocked = false;
    bool mutex_blocked = false;
    int running_times = 0;
    sigjmp_buf env{};
};

/**
 * release all the memory from the system.
 */
void release_all();

/**
 * print a system error.
 * @param str - msg to print.
 */
void print_sys_err(const string& str);

/**
 * print a library error.
 * @param str - msg to print.
 */
void print_lib_err(const string& str);

/**
 * get a pointer to a thread of a given id.
 * @param tid - id of the thread.
 * @return - a pointer to the thread if exists.
 */
thread * get_thread(int tid);

/**
 * check if a given id is legal.
 * @param tid - id to check.
 * @param with_zero - can the id be zero.
 * @return - 0 if id is ok, -1 else.
 */
int check_tid(int tid, bool with_zero);

/**
 * make a context switch between the current running thread to the next one.
 */
void switch_threads();

/**
 *clear the top of the ready queue until the first non - null
 * and not blocked thread is found.
 */
void find_next_available_trd();

/**
 * wake up the next thread in the ready list.
 */
void wake_up_call();

/**
 * translate an address of a variable.
 * @param addr - address to translate.
 * @return - translated address.
 */
address_t translate_address(address_t addr);

/**
 * context switch to the main thread.
 */
void switch_to_main();

/**
 * a handler to signals.
 * @param signal - signal to handle.
 */
void catch_vt_handler(int signal);

/**
 * block signals.
 */
void block_signals();

/**
 * unblock signals.
 */
void unblock_signals();

void erase_from_ready(int tid);




//// ---------- Implementations ------------ ////


int uthread_init(int quantum_usecs)
{
    if (quantum_usecs <= 0)
    {
        print_lib_err("Illegal quantum user seconds given.");
        return -1;
    }

    running_trd = MAIN_TRD;
    threads_num = 1;
    mutex = -1;
    thread_party[0] = new(nothrow) thread();
    if (!thread_party[0])
    {
        print_sys_err("failed to allocate memory.");
        exit(1);
    }
    thread_party[0]->tid = MAIN_TRD;
    thread_party[0]->running_times = 1;
    block_signals();

    // Handler handling!
    sa.sa_handler = &catch_vt_handler;
    sigaction(SIGVTALRM, &sa, nullptr);

    // Configure the timer to expire after quantum_usecs... */
    timer.it_value.tv_sec = 0;		// first time interval, seconds part
    timer.it_value.tv_usec = quantum_usecs;		// first tim    int blocked_threads_num;e interval, microseconds part

    // configure the timer to expire every quantum_usecs after that.
    // following time intervals, seconds part
    timer.it_interval.tv_sec = 0;
    // following time intervals, microseconds part
    timer.it_interval.tv_usec = quantum_usecs;

    total_quantum = 1;

    if (setitimer (ITIMER_VIRTUAL, &timer, nullptr))
    {
        print_sys_err("setitimer error.");
        return -1;
    }
    unblock_signals();
    return 0;
}

int uthread_spawn(void (*f)(void))
{
    block_signals();
    address_t sp, pc;
    if (threads_num >= MAX_THREAD_NUM)
    {
        print_lib_err("Threads number exceeded the max limit.");
        unblock_signals();
        return -1;
    }
    auto * newTrd = new(nothrow) thread();
    if (!newTrd)
    {
        print_sys_err("memory alloc failed.");
        release_all();
        exit(1);
    }

    newTrd->stack = new(nothrow) char[STACK_SIZE];
    if (!newTrd->stack)
    {
        print_sys_err("memory alloc failed.");
        release_all();
        exit(1);
    }

    // Get minimum tid for new thread
    newTrd->tid = threads_num;
    if (!min_tid.empty())
    {
        newTrd->tid = min_tid.top();
        min_tid.pop();
    }

    sp = (address_t) newTrd->stack + STACK_SIZE - sizeof(address_t);
    pc = (address_t)f;
    int val = sigsetjmp(newTrd->env, 1);

    (newTrd->env->__jmpbuf)[JB_SP] = translate_address(sp);
    (newTrd->env->__jmpbuf)[JB_PC] = translate_address(pc);
    sigemptyset(&newTrd->env->__saved_mask);

    thread_party[newTrd->tid] = newTrd;
    threads_num++;

    // Insert to ready list
    ready_list.push_back(newTrd);

    unblock_signals();
    return newTrd->tid;
}

int uthread_terminate(int tid)
{
    block_signals();
    // Terminate the main thread
    if (!tid)
    {
        release_all();
        unblock_signals();
        exit(0);
    }

    int check = check_tid(tid, false);
    if(check)
    {
        unblock_signals();
        return -1;
    }

    erase_from_ready(tid);
    threads_num--;
    min_tid.push(tid);
    delete thread_party[tid]->stack;
    delete thread_party[tid];
    thread_party[tid] = nullptr;
    if (mutex == tid) mutex = -1;

    // if thread terminate itself
    if (running_trd == tid) wake_up_call();

    unblock_signals();
    return 0;
}

int uthread_block(int tid)
{
    block_signals();
    int check = check_tid(tid, true);
    if(check)
    {
        unblock_signals();
        return -1;
    }

    if (!thread_party[tid]->blocked) blocked_threads_num++;
    thread_party[tid]->blocked = true;
    // if thread blocked itself
    if (running_trd == tid)
    {
        switch_threads();
    }
    erase_from_ready(tid);

    unblock_signals();
    return 0;
}

int uthread_resume(int tid)
{
    block_signals();
    int check = check_tid(tid, true);
    if(check)
    {
        unblock_signals();
        return -1;
    }
    if (thread_party[tid]->blocked)
    {
        blocked_threads_num--;
        ready_list.push_back(thread_party[tid]);
    }
    thread_party[tid]->blocked = false;
    unblock_signals();
    return 0;
}

int uthread_mutex_lock()
{
    block_signals();
    if (mutex >= 0)
    {
        if (mutex == running_trd)
        {
            print_lib_err("mutex is already locked by this thread.");
            unblock_signals();
            return -1;
        }
        thread_party[uthread_get_tid()]->mutex_blocked = true;
        switch_threads();
        uthread_mutex_lock();
        unblock_signals();
        return 0;
    }
    mutex = running_trd;
    unblock_signals();
    return 0;
}

int uthread_mutex_unlock()
{
    block_signals();
    if (mutex < 0)
    {
        print_lib_err("mutex is already unlocked.");
        unblock_signals();
        return -1;
    }
    if (mutex >= 0 && mutex != running_trd)
    {
        print_lib_err("only the locking thread can unlock the mutex.");
        return -1;
    }
    mutex = -1;
    unblock_signals();
    return 0;
}

int uthread_get_tid()
{
    return running_trd;
}

int uthread_get_total_quantums()
{
    return total_quantum;
}

int uthread_get_quantums(int tid)
{
    if (!thread_party[tid])
    {
        print_lib_err("no thread with given tid exists.");
        return -1;
    }
    return thread_party[tid]->running_times;
}


void switch_threads()
{
    block_signals();
    if (!thread_party[running_trd]->blocked) ready_list.push_back(thread_party[running_trd]);
    int val = 0;
    // if the current running thread is not the main thread, save the context for
    // context switch.
    val = sigsetjmp(get_thread(running_trd)->env, 1);

    // if val = 1, we just 'woke up' and need to finnish this function.
    if (val)
    {
        unblock_signals();
        return;
    }

    // now, we need to find the next thread that should be running, and wake it up!
    wake_up_call();
}

void release_all()
{
    for (auto & i : thread_party)
    {
        if (i) delete i->stack;
        delete i;
    }
}

thread * get_thread(int tid)
{
    // return the thread pointer in the ds
    return thread_party[tid];
}

void print_sys_err(const string &str)
{
    cerr << "system error: " << str << endl;
}

void print_lib_err(const string &str)
{
    cerr << "thread library error: " << str << endl;
}

int check_tid(int tid, bool with_zero)
{
    if (with_zero && !tid)
    {
        print_lib_err("The main thread cannot be blocked.");
        return -1;
    }

    if ( tid < 0 || tid >= MAX_THREAD_NUM || !thread_party[tid])
    {
        print_lib_err("no thread with given tid exists.");
        return -1;
    }
    return 0;
}


/**
 * remove all nullptr and blocked threads from the
 * ready list until the first available, non - nullptr is found.
 */
void find_next_available_trd()
{
    while (!ready_list.front() || ready_list.front()->mutex_blocked)
    {
        // if the top of the ready list is mutex - blocked
        if (ready_list.front()->mutex_blocked && !ready_list.front()->blocked)
        {
            // if the mutex is free now - free the next available thread and return.
            if (mutex < 0)
            {
            ready_list.front()->mutex_blocked = false;
            return;
            }
            // else - push it back to the end of the list.
            auto temp = ready_list.front();
            ready_list.pop_front();
            ready_list.push_back(temp);
        }
        else ready_list.pop_front();
    }
}


void wake_up_call()
{

    find_next_available_trd();
    // set the thread we found as the running thread, and remove it from the ready list.
    running_trd = ready_list.front()->tid;
    ready_list.pop_front();
    thread_party[running_trd]->running_times++;
    total_quantum++;

    if (setitimer (ITIMER_VIRTUAL, &timer, nullptr))
    {
        print_sys_err("setitimer error.");
    }
    siglongjmp(thread_party[running_trd]->env, 1);
}

void block_signals()
{
    sigaddset(&blocked_sigs, SIGVTALRM);
    sigprocmask(SIG_BLOCK, &blocked_sigs, nullptr);
}

void unblock_signals()
{
    sigprocmask(SIG_UNBLOCK, &blocked_sigs, nullptr);
}

void erase_from_ready(int tid)
{
    for (auto it = ready_list.begin() ;it != ready_list.end(); ++it)
    {
        if (*it == thread_party[tid])
        {
            ready_list.erase(it);
            break;
        }
    }
}


//// ----------- Handlers ------------------ ////



void catch_vt_handler(int signal)
{
    switch_threads();
}