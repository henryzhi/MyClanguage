#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/hrtimer.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
 
static int nr_cpu;
 
atomic_t count;
 
#define TIMER_PERIOD (10 * 1000 * 1000)   // 4              8
static struct work_struct pte_work;
static struct hrtimer timer;
static ktime_t hr_kt;

static void sleep_handle(void)
{
    int cpu = smp_processor_id();
    unsigned int tmpcount = 0; 
    while(!kthread_should_stop()){
      
      if (tmpcount++ <= 10) {
          printk(KERN_INFO "invoking %d..., count:%d\n", cpu, tmpcount);
      }
      else
          break;
      mdelay(10); 
       
    }
    return;  
}

static void pte_work_func(struct work_struct *work) 
{
    unsigned long flags;
    //int cpu = smp_processor_id();
    unsigned int count = 0; 
    //local_irq_save(flags);
    //atomic_inc(&count);
    //local_irq_restore(flags);
    //if (atomic_read(&count) <= 50) 
        //printk(KERN_INFO "invoking %d...\n", cpu);
    while (count++ <= 50);
          
        

}

static enum hrtimer_restart hrtimer_handler(struct hrtimer *timer) {
    hr_kt = ktime_set(0, TIMER_PERIOD);
    hrtimer_forward_now(timer, hr_kt);
   
    pte_work_func(NULL); 
    //schedule_work(&pte_work);
    
    return HRTIMER_RESTART; //HRTIMER_RESTART;
}

static struct task_struct *thread_init(int (*fn)(void *data),
                void *data, int cpu)
{
        struct task_struct *ts;
 
        ts = kthread_create(fn, data, "per_cpu_thread");
        kthread_bind(ts, cpu);
        if (!IS_ERR(ts)) {
                wake_up_process(ts);
        } else {
                printk(KERN_ERR "Failed to bind thread to CPU %d\n", cpu);
        }
        return ts;
}
 
static void thread_sync(void)
{
        atomic_inc(&count);
        while (atomic_read(&count) != nr_cpu);
}

static void my_hrtimer_init(void) {
     //INIT_WORK(&pte_work, pte_work_func);
     hr_kt = ktime_set(0, TIMER_PERIOD);
     hrtimer_init(&timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
     hrtimer_start(&timer, hr_kt, HRTIMER_MODE_REL);
     timer.function = hrtimer_handler;
}

 
static void do_common_stuff(void) {
        int cpu = smp_processor_id();
        unsigned long flags = 0;
 
        printk(KERN_INFO "Syncing %d...\n", cpu);
        local_irq_save(flags);
        thread_sync();
        local_irq_restore(flags);
        printk(KERN_INFO "Syncing done %d.\n", cpu);
}
 
static int per_cpu_thread_fn(void *data) {
        sleep_handle();
        return 0;
}
 
static int main_thread_fn(void *data) {
        int i;
    
        nr_cpu = num_online_cpus();
 
        //atomic_set(&count, 0);
        for (i = 1; i < nr_cpu; ++i) {
                printk("Create thread on %d\n", i);
                thread_init(per_cpu_thread_fn, NULL, i);
        }
 
        sleep_handle();
        return 0;
}
 
static int __init sync_init(void)
{
        thread_init(main_thread_fn, NULL, 0);
        return 0;
}
 
static void __exit sync_exit(void)
{
    
}
 
module_init(sync_init);
module_exit(sync_exit);
 
MODULE_LICENSE("GPL");
