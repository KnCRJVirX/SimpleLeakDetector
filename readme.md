# Simple Memory Leak Detector
一个简单的内存泄漏检查器，个人学习Hook原理用
## 构建
### 使用 MinGW 工具链（推荐）
- 配置
    ```bash
    mkdir build
    cd build
    cmake -G "MinGW Makefiles" ..
    # 需要生成调试版本加上 -DCMAKE_BUILD_TYPE=Debug
    ```
- 生成
    ```bash
    make
    ```

### 使用 Visual Studio 工具链
- 配置
    ```bash
    mkdir build
    cd build
    cmake ..
    ```
- 生成
    ```bash
    cmake --build .
    ```

## 用法
- 基本用法
    ```bash
    .\LeakDetector.exe -exe <ExeFilePath>
    ```
- 可选选项
    - ```-hooker <HookerDllFilePath>``` 指定hook模块的路径（相对路径/绝对路径 均可）
    - ```-log MemoryLeakDetect.log``` 指定日志文件的路径，默认输出到程序文件夹下的```MemoryLeakDetect.log```
    