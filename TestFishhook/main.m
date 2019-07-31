//
//  main.m
//  TestFishhook
//
//  Created by wizet on 2019/7/26.
//  Copyright © 2019 wizet. All rights reserved.
//

#import <UIKit/UIKit.h>
#import "AppDelegate.h"

#import <dlfcn.h>
#import "fishhook.h"


static int (*orig_close)(int);
static int (*orig_open)(const char *, int, ...);

int my_close(int fd) {
    printf("Calling real close(%d)\n", fd);
    return orig_close(fd);
}

int my_open(const char *path, int oflag, ...) {
    va_list ap = {0};
    mode_t mode = 0;
    
    if ((oflag & O_CREAT) != 0) {
        // mode only applies to O_CREAT
        va_start(ap, oflag);
        mode = va_arg(ap, int);
        va_end(ap);
        printf("Calling real open('%s', %d, %d)\n", path, oflag, mode);
        return orig_open(path, oflag, mode);
    } else {
        printf("Calling real open('%s', %d)\n", path, oflag);
        return orig_open(path, oflag, mode);
    }
}


//一个不错的分析 https://draveness.me/fishhook

int main(int argc, char * argv[]) {
    @autoreleasepool {
        
        // 将需要重定位的符号名传给 rebind_symbols， 然后该接口作出相应的替换
        /**
         __data segment 包含多个section相关的符号的绑定。
         __nl_symbol_ptr是一组非懒加载符号的地址的数组（在加载库/目标文件时就确定符号地址的变量/函数）
         __la_symbol_ptr是一组懒加载符号的地址的数据，对于一些导入符号，通常在首次调用某个符号时，会经过一个dyld_stub_binder的例程，将正确的地址替换到__la_symbol_ptr中（也可以在启动时要求dyld绑定这些符号）
         */
        
        
        rebind_symbols((struct rebinding[2]){{"close", my_close, (void *)&orig_close}, {"open", my_open, (void *)&orig_open}}, 2);
        
        
        
        // Open our own binary and print out first 4 bytes (which is the same
        // for all Mach-O binaries on a given architecture)
        
        int fd = open(argv[0], O_RDONLY);
        uint32_t magic_number = 0;
        read(fd, &magic_number, 4);
        printf("Mach-O Magic Number: %x \n", magic_number);// 目标文件的类型 大端还是小端的判定
        close(fd);
        
        
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
