#include "enclave_mm.c"
#include "platform_thread.c"

#include <sm/print.h>
#include <sm/platform/spmp/spmp.h>

static unsigned long form_pmp_size(unsigned long pmp_size) {
  int i;
  // make lower bits all ones
  // 0x00ee --> 0x00ff
  for (i = 1; i <= 32; i = i << 1)
	  pmp_size |= (pmp_size >> i);
  // return (0x00ff + 1) = 0x0100
  return (pmp_size + 1);
}


// 配置PMP0，PMP N-1和sPMP N-1寄存器
int platform_init()
{
  struct pmp_config_t pmp_config;

  //Clear pmp1, this pmp is reserved for allowing kernel
  //to config page table for enclave in enclave's memory.
  //There is no need to broadcast to other hart as every
  //hart will execute this function.
  //clear_pmp(1);
  clear_pmp_and_sync(1);

  // 配置PMP0 寄存器隔离SM
  //config the PMP 0 to protect security monitor
  pmp_config.paddr = (uintptr_t)SM_BASE;
  pmp_config.size = form_pmp_size((unsigned long)SM_SIZE);
  printm("[Penglai Monitor@%s] SM_SIZE:%ld B\n", __func__, (unsigned long)SM_SIZE);
  pmp_config.mode = PMP_A_NAPOT;
  pmp_config.perm = PMP_NO_PERM;
  set_pmp_and_sync(0, pmp_config);

  // 配置PMP N-1 寄存器允许内核访问除前N - 1个PMP隔离的内存区域
  //config the last PMP to allow kernel to access memory
  pmp_config.paddr = 0;
  pmp_config.size = -1UL;
  pmp_config.mode = PMP_A_NAPOT;
  pmp_config.perm = PMP_R | PMP_W | PMP_X;
  //set_pmp(NPMP-1, pmp_config);
  set_pmp_and_sync(NPMP-1, pmp_config);

  // 配置sPMP N-1 寄存器允许 U-mode Enclave 可以访问除 sPMP 隔离的其余内存区域
  //config the last sPMP to allow user to access memory (SRWX=1000)
  struct spmp_config_t spmp_config;
  spmp_config.paddr = 0;
  spmp_config.size = -1UL;
  spmp_config.mode = SPMP_NAPOT;
  spmp_config.perm = SPMP_NO_PERM;
  spmp_config.sbit = SPMP_S;
  set_spmp(NSPMP-1, spmp_config);
  //set_spmp_and_sync(NSPMP-1, spmp_config);

  printm("[Penglai Monitor@%s] setting initial PMP ready\n", __func__);
  return 0;
}
