#include"SeeServ/SeeServ.h"

#include<stdio.h>
#include<stdarg.h>
#include<time.h>

static FILE *_log = NULL;

void see_serv_set_log_file(FILE *file)
{
    _log = file;
}

void _see_serv_log_write(const char *function, const char *fmt, ...)
{
    if (!_log)
        return;
    
    time_t now = time(NULL);
    struct tm local_time;
    localtime_r(&now, &local_time);

    static const char *months[] =
    {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };

    fprintf(_log, "[SeeServ - %02i %s %4i - %02i:%02i:%02i] (in '%s') : ", local_time.tm_mday, months[local_time.tm_mon], local_time.tm_year + 1900, local_time.tm_hour, local_time.tm_min, local_time.tm_sec, function);

    va_list args;
    va_start(args, fmt);
    vfprintf(_log, fmt, args);
    va_end(args);

    fprintf(_log, "\n");
}