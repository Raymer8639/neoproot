/*
 * This file contains SysV IPC core definitions (semaphore/shared memory)
 * Derived from glibc, adapted for proot-scicat with namespace prefixing
 * Built for environments without sys/sem.h availability
 *
 * Copyright (C) 2026 Scicat
 * Copyright (C) 1995-2020 Free Software Foundation, Inc. (original glibc definitions)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef SYSVIPC_SYS_H
#define SYSVIPC_SYS_H

#include <stdint.h>
#include <sys/ipc.h>   /* For struct ipc_perm */
#include <sys/msg.h>   /* For ipc_perm compatibility */

/* ========================== Semaphore Definitions ========================== */

/**
 * semop() 操作标志：进程退出时撤销操作
 * 对应 glibc SEM_UNDO，添加 SYSVIPC_ 命名空间前缀
 */
#define SYSVIPC_SEM_UNDO	0x1000

/**
 * semctl() 控制命令（对应 glibc 定义，添加 SYSVIPC_ 前缀）
 */
#define SYSVIPC_GETPID		11	/* 获取最后操作该信号量的进程PID */
#define SYSVIPC_GETVAL		12	/* 获取指定信号量的当前值 */
#define SYSVIPC_GETALL		13	/* 获取所有信号量的当前值 */
#define SYSVIPC_GETNCNT		14	/* 获取等待信号量值递增的进程数 */
#define SYSVIPC_GETZCNT		15	/* 获取等待信号量值为0的进程数 */
#define SYSVIPC_SETVAL		16	/* 设置指定信号量的值 */
#define SYSVIPC_SETALL		17	/* 设置所有信号量的值 */
#define SYSVIPC_SEM_STAT	18	/* 获取指定信号量集的状态信息 */
#define SYSVIPC_SEM_INFO	19	/* 获取系统信号量资源限制信息 */
#define SYSVIPC_SEM_STAT_ANY	20	/* 获取任意可用信号量集的状态信息 */

/**
 * semop() 操作结构体
 * 对应 glibc struct sembuf，添加 SYSVIPC_ 命名空间前缀
 */
struct SysVIpcSembuf {
    uint16_t sem_num;  /* 信号量在信号量集中的索引（0-based） */
    int16_t  sem_op;   /* 操作类型（正数：递增，负数：递减，0：等待为0） */
    int16_t  sem_flg;  /* 操作标志（SYSVIPC_SEM_UNDO 等） */
};

/**
 * 系统信号量资源限制信息结构体
 * 对应 glibc struct seminfo，添加 SYSVIPC_ 命名空间前缀
 */
struct SysVIpcSeminfo {
    int semmap;  /* 信号量映射表项数（已废弃，保留兼容性） */
    int semmni;  /* 系统最大信号量集数量 */
    int semmns;  /* 系统最大信号量总数 */
    int semmnu;  /* 系统最大 undo 结构数量（已废弃，保留兼容性） */
    int semmsl;  /* 单个信号量集最大信号量数 */
    int semopm;  /* 单个 semop() 调用最大操作数 */
    int semume;  /* 单个进程最大 undo 操作数（已废弃，保留兼容性） */
    int semusz;  /* undo 结构大小（已废弃，保留兼容性） */
    int semvmx;  /* 信号量最大值 */
    int semaem;  /* 信号量调整最大值（已废弃，保留兼容性） */
};

/* ======================== Shared Memory Definitions ======================== */

/**
 * 共享内存段状态信息结构体
 * 对应 glibc struct shmid_ds，添加 SYSVIPC_ 命名空间前缀，64位兼容
 */
struct SysVIpcShmidDs {
    struct ipc_perm shm_perm;  /* 共享内存段权限控制结构体 */
    size_t          shm_segsz; /* 共享内存段大小（字节） */
    int64_t         shm_atime; /* 最后一次 shmat() 调用时间（UNIX时间戳） */
    int64_t         shm_dtime; /* 最后一次 shmdt() 调用时间（UNIX时间戳） */
    int64_t         shm_ctime; /* 最后一次 shmctl() 修改时间（UNIX时间戳） */
    int32_t         shm_cpid;  /* 创建者进程PID */
    int32_t         shm_lpid;  /* 最后一次操作的进程PID */
    uint64_t        shm_nattch;/* 当前附加到该段的进程数 */
    uint64_t        __glibc_reserved5; /* glibc 预留字段，保留兼容性 */
    uint64_t        __glibc_reserved6; /* glibc 预留字段，保留兼容性 */
};

/* ========================== Common Definitions ========================== */

/**
 * IPC 控制命令标志：强制使用64位结构体
 * 对应 glibc __IPC_64，确保32位架构下也使用64位时间戳/计数器字段
 */
#define SYSVIPC_IPC_64      0x100

/**
 * IPC 控制命令：获取系统资源信息（对应 glibc IPC_INFO）
 */
#define SYSVIPC_IPC_INFO	3

#endif /* SYSVIPC_SYS_H */
