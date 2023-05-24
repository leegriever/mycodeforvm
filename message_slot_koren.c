/* BASED ON REC06 EXAMPLE AS TEMPLATE */ 

#include <linux/slab.h> // kmalloc, kfree
#include <linux/uaccess.h>  /* for get_user and put_user */
#include "message_slot.h"
MODULE_LICENSE("GPL");

typedef enum status {
  MSGSIZE = -EMSGSIZE, // -3432
  FAULT = -EFAULT, // -3408
  WOULDBLOCK = -EWOULDBLOCK, // -3046
  INVAL = -EINVAL, // -3021
  NOSPC = -ENOSPC, // -133
  NOMEM = -ENOMEM, // -132
  FAILURE = -1,    // -1
  SUCCESS          // 0 
} status_t;

typedef enum boolean {
  TRUE = 0,
  FALSE
} bool_t;

#define SET_STATUS(cond, status, error_msg){                              \
    if ((cond)){                                                          \
      printk(KERN_ERR "%s\n", (error_msg));                             \
       return (status);                                                    \
    }                                                                     \
}                                                                         \

static chnl_t * slots[MAX_SLOTS + 1] = {NULL}; 

chnl_t * get_channel(msg_dat_t * data){
  chnl_t * channel = NULL;
  if (NULL == data){
    return NULL;
  }
  CHECK_SLOT_VALUE(data->minor, NULL);
  for (channel = slots[data->minor]; channel != NULL; channel = channel->next){
    if(channel->id == data->channel_id){
      return channel;
    }
  }
  return channel;
}

//================== DEVICE FUNCTIONS ===========================
static int device_open( struct inode* inode,
                        struct file*  file ){
  msg_dat_t * data = NULL;

  CHECK_SLOT_VALUE(iminor(inode), FAILURE);
  data = (msg_dat_t *)kmalloc(sizeof(msg_dat_t), GFP_KERNEL);
  SET_STATUS(NULL == data, FAILURE, "failed to allocate memory");
  data->minor = iminor(inode);
  data->channel_id = DEFAULT_CHANNEL_ID;
  file->private_data = (void *) data;
  return SUCCESS;

}


//---------------------------------------------------------------
// a process which has already opened
// the device file attempts to read from it
static ssize_t device_read( struct file* file,
                            char __user* buffer,
                            size_t       length,
                            loff_t*      offset )
{
  msg_t * message = NULL;
  msg_dat_t * data = NULL;
  chnl_t * channel = NULL;
  int i = 0;
  int result = 0;

  SET_STATUS(NULL == buffer, INVAL, "read no buffer from user");
  SET_STATUS(length <= 0, INVAL, "read no space to read");

  data = (msg_dat_t *)file->private_data;
  SET_STATUS(NULL == data, INVAL, "read no data from file");
  CHECK_SLOT_VALUE(data->minor, INVAL);
  SET_STATUS(0 == data->channel_id, INVAL, "read channel wasn't init");
  channel = get_channel(data);
  SET_STATUS(NULL == channel, WOULDBLOCK, "read channel is invalid");
  message = channel->head;
  SET_STATUS(NULL == message, WOULDBLOCK, "read message is invalid");
  SET_STATUS(length < message->len, NOSPC, "read message is longer than expected");

  for(i = 0; i < message->len; i++){
    result = put_user((message->message_data)[i], &buffer[i]);
    SET_STATUS(0 != result, FAULT, "read couldn't send data to user space");
  }
  return message->len;
}

//---------------------------------------------------------------
// a processs which has already opened
// the device file attempts to write to it
static ssize_t device_write( struct file*       file,
                             const char __user* buffer,
                             size_t             length,
                             loff_t*            offset){
  msg_dat_t * data = NULL;
  chnl_t * channel = NULL;
  msg_t * msg = NULL;
  int i = 0;
  int result = 0;

  SET_STATUS(NULL == buffer, INVAL, "write no buffer was supplied");
  SET_STATUS(0 >= length, MSGSIZE, "write no valid len");
  SET_STATUS(MAX_BUF_SIZE < length, MSGSIZE, "write no valid len");


  data = (msg_dat_t*)(file->private_data);
  SET_STATUS(0 >= data->channel_id, INVAL, "write no valid channel number");
  CHECK_SLOT_VALUE(data->minor, INVAL);

  channel = get_channel(data);
  SET_STATUS(NULL == channel, INVAL, "write no valid channel");

  msg = (msg_t *)kmalloc(sizeof(msg_t), GFP_KERNEL);
  SET_STATUS(NULL == msg, NOMEM, "write couldn't allocate");
  
  for(i = 0; i < length; i++){
    result = get_user((msg->message_data)[i], &buffer[i]);
    SET_STATUS(0 != result, FAULT, "write couldn't copy");
  }
  msg->len = length;
  msg -> next = channel -> head;
  channel -> head = msg;
  return length;


}

//----------------------------------------------------------------
static long device_ioctl( struct   file* file,
                          unsigned int   ioctl_command_id,
                          unsigned long  ioctl_param ){
  chnl_t * channel = NULL;
  msg_dat_t * data = NULL;
  bool_t is_exist = FALSE;
  SET_STATUS((MSG_SLOT_CHANNEL != ioctl_command_id), INVAL, "ioctl wrong command");
  SET_STATUS(0 >= ioctl_param, INVAL, "ioctl wrong channel id");
  data = (msg_dat_t *)file->private_data;
  SET_STATUS(NULL == data, INVAL, "ioctl wrong channel id");
  CHECK_SLOT_VALUE(data->minor, INVAL);
  // printk(KERN_EMERG "IOCTL: channel is: %lu\n", ioctl_param);

  if(NULL == slots[data->minor]){
    slots[data->minor] = (chnl_t *) kmalloc(sizeof(chnl_t), GFP_KERNEL);
    SET_STATUS(NULL == slots[data->minor], NOMEM, "ioctl couldn't allocate memory");
    data->channel_id = ioctl_param;
    slots[data->minor] -> id = ioctl_param;
    slots[data->minor] -> head = NULL;
    slots[data->minor] -> next = NULL;
    return SUCCESS;  
  }
  // let's find the last channel's pointer! and check it's existens  
  channel = slots[data->minor];
  while (NULL != channel->next){
    if (channel->id == ioctl_param){
      break;
    }
    channel = channel->next;
  }

  if (channel->id == ioctl_param){
    is_exist = TRUE;
  }
  if (FALSE == is_exist){
    // printk(KERN_EMERG "DEBUG: adding new channel %lu\n", ioctl_param);
    channel->next = (chnl_t *) kmalloc(sizeof(chnl_t), GFP_KERNEL);
    SET_STATUS(NULL == channel->next, NOMEM, "ioctl couldn't allocate memory");
    channel -> next -> id = ioctl_param;
    channel -> next -> head = NULL;
    channel -> next -> next = NULL;
  }
  data->channel_id = ioctl_param;
  return SUCCESS;

}


//==================== DEVICE SETUP =============================

// This structure will hold the functions to be called
// when a process does something to the device we created
struct file_operations Fops = {
  .owner          = THIS_MODULE, 
  .read           = device_read,
  .write          = device_write,
  .open           = device_open,
  .unlocked_ioctl = device_ioctl,
};

//---------------------------------------------------------------
// Initialize the module - Register the character device
static int __init simple_init(void)
{
  int major = 0;
  major = register_chrdev(MAJOR_NUM, DEVICE_FILE_NAME, &Fops);
  if (0 > major){
    return major;
  }
  printk( "Registeration is successful. ");
  printk( "If you want to talk to the device driver,\n" );
  printk( "you have to create a device file:\n" );
  printk( "mknod /dev/%s c %d 0\n", DEVICE_FILE_NAME, MAJOR_NUM );
  printk( "You can echo/cat to/from the device file.\n" );
  printk( "Dont forget to rm the device file and rmmod when you're done\n" );

  return SUCCESS;
}

//---------------------------------------------------------------
void msg_free(msg_t * msg){
  msg_t * cur = NULL;
  msg_t * next = NULL;
  if (NULL == msg){
    return;
  }
  cur = msg;
  while (NULL != cur){
    next = cur ->next;
    kfree(cur);
    cur = next;
  }
}

void chnl_free(chnl_t * channel){
  chnl_t * next = NULL;
  chnl_t * cur = NULL;
  if (NULL == channel){
    return;
  }
  cur = channel;
  while (NULL != cur){
    next = cur->next;
    msg_free(cur->head);
    kfree(cur);
    cur = next;
  }
}

static void __exit simple_cleanup(void)
{
  // Unregister the device
  // Should always succeed
  int i = 0;
  for (i=0; i <= MAX_SLOTS; i++){
    chnl_free(slots[i]);
    slots[i] = NULL;
  }
  // kfree(slots);
  unregister_chrdev(MAJOR_NUM, DEVICE_RANGE_NAME);
}

//---------------------------------------------------------------
module_init(simple_init);
module_exit(simple_cleanup);

//========================= END OF FILE =========================
