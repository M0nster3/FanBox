# FanBox
Some anti-sandbox codes, copy directly to strengthen your own ShellCode

1、前言

主要为了便利做项目的时候，自己的Shellcode被传到沙箱里面解析，以及防止自己的代码被调试，而做的一些规避操作,大部分代码是从这个项目提取的，一个很不错的项目https://github.com/LordNoteworthy/al-khaser。

2、相关接口以及功能

| API                         | 功能                                              |
| --------------------------- | ------------------------------------------------- |
| NumberOfProcessors          | 处理器数量                                        |
| serial_number_bios_wmi      | WMIC查看BIOS序列号                                |
| number_cores_wmi            | WMIC查看CPU核心数                                 |
| mouse_movement              | 检查鼠标移动                                      |
| memory_space                | 检查内存空间                                      |
| accelerated_sleep           | 检测时间是否加速（谨慎使用由于检测时间较长1分钟） |
| VMDriverServices            | 检测VMWARE                                        |
| registry_services_disk_enum | 检测注册表VMWARE参数                              |
| analysis                    | 恶意程序分析工具                                  |
| IsDebuggerPresentAPI        | 一些VScode等调试API                               |
| we_chat                     | 判断是否存在微信                                  |



