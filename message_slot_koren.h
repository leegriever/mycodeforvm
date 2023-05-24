#ifndef __MSG_SLT__
#define __MSG_SLT__

// Declare what kind of code we want
// from the header files. Defining __KERNEL__
// and MODULE allows us to access kernel-level
// code not usually available to userspace programs.
#undef __KERNEL__
#define __KERNEL__
#undef MODULE
#define MODULE


#include <linux/kernel.h>   /* We're doing kernel work */
#include <linux/module.h>   /* Specifically, a module */
#include <linux/fs.h>       /* for register_chrdev */
#include <linux/string.h>   /* for memset. NOTE - not string.h!*/

#define MAX_BUF_SIZE            (128)
#define MAX_SLOTS               (256)
#define DEFAULT_CHANNEL_ID      (0)
#define MAJOR_NUM               (235)
#define MSG_SLOT_CHANNEL        _IOW(MAJOR_NUM, 0, unsigned long)
#define DEVICE_RANGE_NAME       ("message_slot")
#define DEVICE_FILE_NAME        ("message_slot")


#define CHECK_SLOT_VALUE(slot_val, error_code){                           \
      if((slot_val) >  MAX_SLOTS || (slot_val) < 0){                      \
        printk("Error: Max minor numer can be 256 but got %d", slot_val); \
        return (error_code);                                              \
      }                                                                   \
}                                                                         \

typedef struct message {
  int len;
  char message_data[MAX_BUF_SIZE];
  struct message * next;
} msg_t;

typedef struct channel { 
  unsigned long id;
  msg_t * head;
  struct channel * next;
} chnl_t;

typedef struct message_data {
  int minor;
  unsigned long channel_id;
} msg_dat_t; 

// static int device_open( struct inode* inode,
//                         struct file*  file );

// static ssize_t device_read( struct file* file,
//                             char __user* buffer,
//                             size_t       length,
//                             loff_t*      offset );

// static ssize_t device_write( struct file*       file,
//                              const char __user* buffer,
//                              size_t             length,
//                              loff_t*            offset);

// static long device_ioctl( struct   file* file,
//                           unsigned int   ioctl_command_id,
//                           unsigned long  ioctl_param );

#endif // __MSG_SLT__