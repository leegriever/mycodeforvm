// This code is based on rec06 

#undef __KERNEL__
#define __KERNEL__
#undef MODULE
#define MODULE


#include <linux/kernel.h>   /* We're doing kernel work */
#include <linux/module.h>   /* Specifically, a module */
#include <linux/fs.h>       /* for register_chrdev */
#include <linux/uaccess.h>  /* for get_user and put_user */
#include <linux/string.h>   /* for memset. NOTE - not string.h!*/

//Our custom definitions of IOCTL operations
#include "message_slot.h" 

MODULE_LICENSE("GPL");

typedef struct channel {
    unsigned long id;
    struct  channel* next;
    int msg_len;
    char msg[MAX_MSG_LEN];
} channel;

typedef struct slot {
    int minor;
    struct channel* head;
} slot;

typedef struct file_info
{
  int minor;
  unsigned long id;
} fd_info;

typedef enum errors{
  REG,
  ARG,
  MINOR,
  ALLOC,
  MSG_LEN,
  NO_MESSAGE,
  BUFF_LEN,
} error;

int validity(int num, error e);
channel * find_channel(fd_info * info);

static slot* slots[MAX_SLOTS+1] = {NULL};


int validity(int num, error e){
  if (e == MINOR){
    if (num > MAX_SLOTS || num < 0){
      printk(KERN_ERR "%s Error - illegal minor number  %d\n")
      return FAIL;
    }
  }
  if (e == ALLOC && num){
    printk(KERN_ERR "%s Error - failed allocating memory  %d\n")
    return FAIL;
  }
  if (e == ARG && num){
    return -EINVAL;
  }
  if (e == NO_MESSAGE && num == 0){
    return -EWOULDBLOCK;
  }
  if (e == BUFF_LEN && num){
    return -ENOSPC;
  }
  if (e == REG && num){
    return FAIL;
  }
  if (e == MSG_LEN){
    if (num <= 0 || num > MAX_MSG_LEN){
      return -EMSGSIZE;
    }
  }
}

channel * find_channel(fd_info * info){
  channel * curr_channel;
  slot * curr_slot;
  if ((info == NULL) || (info->minor == NULL)){
    curr_channel = NULL;
  } 
  else{
    curr_slot = slots[info->minor];
    curr_channel = curr_slot->head;
    while ((curr_channel != NULL) && (curr_channel->id != info->id))
    {
     curr_channel = curr_channel->next;
    }
    if (curr_channel != NULL){
      return curr_channel;
    }
    curr_channel->next = (channel*) kmalloc(sizeof(channel), GFP_KERNEL);
    validity(curr_channel->next == NULL, ALLOC);
    channel->next->id = info->id;
    channel->next->next = NULL;
    channel->next->msg_len = 0;
  }
  validity(curr_channel == NULL, REG);
  return curr_channel;
}

//================== DEVICE FUNCTIONS ===========================
static int device_open( struct inode* inode,
                        struct file*  file )
{
  slot *curr_slot = NULL;
  fd_info * info = NULL;
  int curr_minor = iminor(inode);
  validity(curr_minor, MINOR); 
  // slot doesn't exist
  if (slots[curr_minor] == NULL){
    curr_slot = (slot*)kmalloc(sizeof(slot), GFP_KERNEL);
    validity(curr_slot == NULL, ALLOC);
    curr_slot->minor = curr_minor;
    curr_slot->head = NULL;
    slots[curr_minor] = curr_slot;
  }
  info = (fd_info *)kmalloc(sizeof(fd_info), GFP_KERNEL);
  validity(info == NULL, ALLOC);
  info->minor = curr_minor;
  info->id = 0;    // channel_id for file will known only in ioctl
  file->private_data = (void *) info;

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
  int i;
  channel * curr_channel;
  fd_info * info = (fd_info *)file->private_data;

  // check oif a channel has been set on the fd
  validity(info == NULL, ARG);
  validity(info->id == 0, ARG);
  // user's buffer vallidate
  validity(buffer == NULL, REG);
  // DELETE !!!! check access_ok val 
  // explanation for acsses_ok use here
  //https://stackoverflow.com/questions/6887057/linux-kernel-userspace-buffers-do-access-ok-and-wait-create-a-race-condition
  validity(!access_ok(buffer, length), ARG);
  
  curr_channel = find_channel(info);
  validity(curr_channel->msg_len, NO_MESSAGE);
  validity(length < (curr_channel->msg_len), BUFF_LEN);

  for (i = 0, i < curr_channel->msg_len, i++){
    // DELETE !!! CHECK if it works, MIGHT NEED TO SPLIT 
    validity((put_user((curr_channel->msg)[i], &buffer[i]) < 0) , REG);
  }
  return curr_channel->msg_len;
}

//---------------------------------------------------------------
// a processs which has already opened
// the device file attempts to write to it
static ssize_t device_write( struct file*       file,
                             const char __user* buffer,
                             size_t             length,
                             loff_t*            offset)
{
  int i;
  channel * curr_channel;
  fd_info * info = (fd_info *)file->private_data;
  
  // check if a channel has been set on the fd
  validity(info == NULL, ARG);
  validity(info->id == 0, ARG);
  validity(buffer == NULL, REG);
  // explanation for acsses_ok use here
  //https://stackoverflow.com/questions/6887057/linux-kernel-userspace-buffers-do-access-ok-and-wait-create-a-race-condition
  validity(!access_ok(buffer, length), ARG);
  // validate msg len
  validity(length, MSG_LEN);
  curr_channel = find_channel(info);

  for (i = 0, i < length, i++){
    validity((put_user((curr_channel->msg)[i], &buffer[i]) < 0) , REG);
  }
  curr_channel->msg_len = length;

  return curr_channel->msg_len;
}

//----------------------------------------------------------------
static long device_ioctl( struct   file* file,
                          unsigned int   ioctl_command_id,
                          unsigned long  ioctl_param )
{
  // can change this with validity ARG
  if ((ioctl_command_id != MSG_SLOT_CHANNEL) || (ioctl_param == 0)){
    return -EINVAL;
  }
  fd_info * info = (fd_info *)file->private_data;
  validity(info == NULL, ARG);
  // associate channel id with the fd
  info->id = ioctl_param;

  return SUCCESS;
}

//----------------------------------------------------------------
static int device_release( struct inode* inode,
                           struct file*  file)
{
  kfree(file->private_data);
  return SUCCESS;
}

//==================== DEVICE SETUP =============================

// This structure will hold the functions to be called
// when a process does something to the device we created
struct file_operations Fops = {
  .owner	  = THIS_MODULE, 
  .read           = device_read,
  .write          = device_write,
  .open           = device_open,
  .unlocked_ioctl = device_ioctl,
  .release = device_release,
};

//---------------------------------------------------------------
// Initialize the module - Register the character device
static int __init ms_init(void)
{
  int rc = -1;
 
  // Register driver capabilities. Obtain major num
  rc = register_chrdev(MAJOR, DEVICE_RANGE_NAME, &Fops);

  // Negative values signify an error
  if( rc < 0 ) {
    printk(KERN_ERR "%s registraion failed for  %d\n", DEVICE_FILE_NAME,MAJOR);
    return rc;
  }

  return SUCCESS;
}

//---------------------------------------------------------------
static void __exit ms_cleanup(void)
{
  int i;
  channel * curr_channel = NULL;
  channel * tmp_channel = NULL;
  slot * curr_slot;

  for (i = 0, i < MAX_SLOTS + 1, i++){
    if (slots[i] == NULL){
      continue;
    }
    curr_channel = slots[i]->head;
    while (curr_channel != NULL){
      tmp_channel = curr_channel->next;
      kfree(curr_channel->next);
      curr_channel = tmp;
    }
    kfree(slots[i]);
  }
  // Unregister the device
  unregister_chrdev(MAJOR, DEVICE_RANGE_NAME);
}

//---------------------------------------------------------------
module_init(ms_init);
module_exit(ms_cleanup);

//========================= END OF FILE =========================
