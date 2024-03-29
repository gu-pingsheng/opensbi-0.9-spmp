//#include <sm/atomic.h>
#include <sbi/riscv_atomic.h>
#include <sm/sm.h>
#include <sm/pmp.h>
#include <sm/enclave.h>
#include <sm/attest.h>
#include <sm/math.h>
#include <sbi/sbi_console.h>

#include <sbi/sbi_string.h>
#include <sm/platform/spmp/spmp.h>


//static int sm_initialized = 0;
//static spinlock_t sm_init_lock = SPINLOCK_INIT;

void sm_init()
{
  // 初始化PMP0，PMP N-1寄存器，sPMP N-1寄存器
  platform_init();
  // 初始化SM的私钥和公钥
  attest_init();
}

uintptr_t sm_mm_init(uintptr_t paddr, unsigned long size)
{
  uintptr_t retval = 0;

  printm("[Penglai Monitor] %s invoked\r\n",__func__);

  printm("[Penglai Monitor] %s paddr:0x%lx, size:0x%lx\r\n",__func__, paddr, size);
  /*DEBUG: Dump PMP registers here */
  dump_pmps();
  // 将内核分配的连续物理内存，通过配置PMP寄存器将其隔离保护
  retval = mm_init(paddr, size);
  /*DEBUG: Dump PMP registers here */
  dump_pmps();

  printm("[Penglai Monitor] %s ret:%ld \r\n",__func__, retval);
  return retval;
}

uintptr_t sm_mm_extend(uintptr_t paddr, unsigned long size)
{
  uintptr_t retval = 0;
  printm("[Penglai Monitor] %s invoked\r\n",__func__);
  // 内存扩展依然通过驱动分配连续的地址空间，并通过配置PMP寄存器保护这片内存
  retval = mm_init(paddr, size);

  printm("[Penglai Monitor] %s return:%ld\r\n",__func__, retval);
  return retval;
}

uintptr_t sm_debug_print(uintptr_t* regs, uintptr_t arg0)
{
  print_buddy_system();
  return 0;
}

uintptr_t sm_alloc_enclave_mem(uintptr_t mm_alloc_arg)
{
  //mm_alloc_arg_t 中的字段：req_size; resp_addr; resp_size;
  struct mm_alloc_arg_t mm_alloc_arg_local;
  uintptr_t retval = 0;

  printm("[Penglai Monitor] %s invoked\r\n",__func__);

  retval = copy_from_host(&mm_alloc_arg_local,
      (struct mm_alloc_arg_t*)mm_alloc_arg,
      sizeof(struct mm_alloc_arg_t));
  if(retval != 0)
  {
    printm_err("M mode: sm_alloc_enclave_mem: unknown error happended when copy from host\r\n");
    return ENCLAVE_ERROR;
  }

  dump_pmps();
  unsigned long resp_size = 0;
  
  // 通过查找已经配置完PMP寄存器的mm_region分配enclave内存
  void* paddr = mm_alloc(mm_alloc_arg_local.req_size, &resp_size);
  if(paddr == NULL)
  {
    printm("M mode: sm_alloc_enclave_mem: no enough memory\r\n");
    return ENCLAVE_NO_MEMORY;
  }
  dump_pmps();

  // 请求SM分配完内存之后，需要授予内核访问这块内存的权限，内核将会加载Enclave可执行文件，配置Enclave 页表，管理free_mem
  //grant kernel access to this memory
  if(grant_kernel_access(paddr, resp_size) != 0)
  {
    printm_err("M mode: ERROR: faile to grant kernel access to pa 0x%lx, size 0x%lx\r\n", (unsigned long) paddr, resp_size);
    mm_free(paddr, resp_size);
    return ENCLAVE_ERROR;
  }

  mm_alloc_arg_local.resp_addr = (uintptr_t)paddr;
  mm_alloc_arg_local.resp_size = resp_size;

  retval = copy_to_host((struct mm_alloc_arg_t*)mm_alloc_arg,
      &mm_alloc_arg_local,
      sizeof(struct mm_alloc_arg_t));
  if(retval != 0)
  {
    printm_err("M mode: sm_alloc_enclave_mem: unknown error happended when copy to host\r\n");
    return ENCLAVE_ERROR;
  }

  printm("[Penglai Monitor] %s return:%ld\r\n",__func__, retval);

  return ENCLAVE_SUCCESS;
}

uintptr_t sm_create_enclave(uintptr_t enclave_sbi_param)
{
  struct enclave_sbi_param_t enclave_sbi_param_local;
  uintptr_t retval = 0;
  struct enclave_t* enclave;
  unsigned int eid;

  printm("[Penglai Monitor] %s invoked\r\n",__func__);

  retval = copy_from_host(&enclave_sbi_param_local,
      (struct enclave_sbi_param_t*)enclave_sbi_param,
      sizeof(struct enclave_sbi_param_t));
  if(retval != 0)
  {
    printm_err("M mode: sm_create_enclave: unknown error happended when copy from host\r\n");
    return ENCLAVE_ERROR;
  }

  void* paddr = (void*)enclave_sbi_param_local.paddr;
  unsigned long size = (unsigned long)enclave_sbi_param_local.size;

  // 在创建enclave之前，需要撤销内核对Enclave内存访问的权限
  if(retrieve_kernel_access(paddr, size) != 0)
  {
    mm_free(paddr, size);
    return -1UL;
  }

  retval = create_enclave_m(enclave_sbi_param_local);
  eid = *(enclave_sbi_param_local.eid_ptr);
  enclave = get_enclave(eid);

  sbi_memset(enclave->enclave_spmp_context, 0, sizeof(struct spmp_config_t) * NSPMP);
  
  // 创建enclave之后，运行enclave之前，需要配置sPMP0和sPMP1寄存器，
  //config the enclave sPMP structure to allow enclave to access memory
  enclave->enclave_spmp_context[0].paddr = enclave->paddr;
  enclave->enclave_spmp_context[0].size = enclave->size;
  enclave->enclave_spmp_context[0].mode = SPMP_NAPOT;
  enclave->enclave_spmp_context[0].perm = SPMP_R | SPMP_W | SPMP_X;

//set the spmp_1 to let enclave access kbuffer shared memory
  enclave->enclave_spmp_context[1].paddr = enclave_sbi_param_local.kbuffer_paddr;
  enclave->enclave_spmp_context[1].size = enclave_sbi_param_local.kbuffer_size;
  enclave->enclave_spmp_context[1].mode = SPMP_NAPOT;
  enclave->enclave_spmp_context[1].perm = SPMP_R | SPMP_W | SPMP_X;
  printm("[Penglai Monitor] %s, kbuffer_paddr: 0x%lx\n", __func__, enclave_sbi_param_local.kbuffer_paddr);
  sbi_memset(enclave->thread_context.host_spmp_context, 0, sizeof(struct spmp_config_t) * (NSPMP-1));

  for(int i = 0; i < (NSPMP-1); i++)
  {
  	clear_spmp(i);  
  }

  //config the last sPMP to allow user to access memory
  enclave->thread_context.host_spmp_context[NSPMP-1].paddr = 0;
  enclave->thread_context.host_spmp_context[NSPMP-1].size = -1UL;
  enclave->thread_context.host_spmp_context[NSPMP-1].mode = SPMP_NAPOT;
  enclave->thread_context.host_spmp_context[NSPMP-1].perm = SPMP_NO_PERM;
  enclave->thread_context.host_spmp_context[NSPMP-1].sbit = SPMP_S;
  set_spmp(NSPMP-1, enclave->thread_context.host_spmp_context[NSPMP-1]); 
  
  printm("[Penglai Monitor] %s created return value:%ld \r\n",__func__, retval);
  return retval;
}

uintptr_t sm_attest_enclave(uintptr_t eid, uintptr_t report, uintptr_t nonce)
{
  uintptr_t retval;
  printm("[Penglai Monitor] %s invoked, eid:%ld\r\n",__func__, eid);

  retval = attest_enclave(eid, report, nonce);

  printm("[Penglai Monitor] %s return: %ld\r\n",__func__, retval);

  return retval;
}

uintptr_t sm_run_enclave(uintptr_t* regs, unsigned long eid)
{
  uintptr_t retval;
  printm("[Penglai Monitor] %s invoked, eid:%ld\r\n",__func__, eid);
#if 0
  dump_pmps();
  printm_err("\n");
#endif
  retval = run_enclave(regs, (unsigned int)eid);
#if 0
  dump_pmps();
  printm_err("\n");
  dump_spmps();
#endif
  printm("[Penglai Monitor] %s return: %ld\r\n",__func__, retval);

  return retval;
}

uintptr_t sm_stop_enclave(uintptr_t* regs, unsigned long eid)
{
  uintptr_t retval;
  printm("[Penglai Monitor] %s invoked, eid:%ld\r\n",__func__, eid);

  retval = stop_enclave(regs, (unsigned int)eid);

  printm("[Penglai Monitor] %s return: %ld\r\n",__func__, retval);
  return retval;
}

uintptr_t sm_resume_enclave(uintptr_t* regs, unsigned long eid)
{
  uintptr_t retval = 0;
  uintptr_t resume_func_id = regs[11];

  switch(resume_func_id)
  {
    case RESUME_FROM_TIMER_IRQ:
      retval = resume_enclave(regs, eid);
      break;
    case RESUME_FROM_STOP:
      retval = resume_from_stop(regs, eid);
      break;
    case RESUME_FROM_OCALL:
      retval = resume_from_ocall(regs, eid);
      break;
    default:
      break;
  }

  return retval;
}

uintptr_t sm_exit_enclave(uintptr_t* regs, unsigned long retval)
{
  uintptr_t ret;
  printm("[Penglai Monitor] %s invoked\r\n",__func__);

  ret = exit_enclave(regs, retval);

  printm("[Penglai Monitor] %s return: %ld\r\n",__func__, ret);

  return ret;
}

uintptr_t sm_enclave_ocall(uintptr_t* regs, uintptr_t ocall_id, uintptr_t arg0, uintptr_t arg1)
{
  printm("[Penglai Monitor] %s invoked\r\n",__func__);
  uintptr_t ret = 0;
  switch(ocall_id)
  {
    case OCALL_SYS_WRITE:
      ret = enclave_sys_write(regs);
      break;
    case OCALL_USER_DEFINED:
      ret = enclave_user_defined_ocall(regs, arg0);
      break;
    default:
      printm_err("[Penglai Monitor@%s] wrong ocall_id(%ld)\r\n", __func__, ocall_id);
      ret = -1UL;
      break;
  }
  return ret;
}

/**
 * \brief Retrun key to enclave.
 * 
 * \param regs          The enclave regs.
 * \param salt_va       Salt pointer in enclave address space.
 * \param salt_len      Salt length in bytes.
 * \param key_buf_va    Key buffer pointer in enclave address space.
 * \param key_buf_len   Key buffer length in bytes.
 */
uintptr_t sm_enclave_get_key(uintptr_t* regs, uintptr_t salt_va, uintptr_t salt_len,
    uintptr_t key_buf_va, uintptr_t key_buf_len)
{
  uintptr_t ret = 0;

  ret = enclave_derive_seal_key(regs, salt_va, salt_len, key_buf_va, key_buf_len);

  return ret;
}

/**
 * \brief This transitional function is used to destroy the enclave.
 *
 * \param regs The host reg.
 * \param enclave_eid The enclave id.
 */
uintptr_t sm_destroy_enclave(uintptr_t *regs, uintptr_t enclave_id)
{
  uintptr_t ret = 0;
  printm("[Penglai Monitor] %s invoked\r\n",__func__);

  ret = destroy_enclave(regs, enclave_id);

  printm("[Penglai Monitor] %s return: %ld\r\n",__func__, ret);

  return ret;
}

uintptr_t sm_do_timer_irq(uintptr_t *regs, uintptr_t mcause, uintptr_t mepc)
{
  uintptr_t ret;

  ret = do_timer_irq(regs, mcause, mepc);

  regs[10] = 0; //no errors in all cases for timer handler
  regs[11] = ret; //value
  return ret;
}
