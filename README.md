# FCM

FCM（Fuck CheatMaker）是一个单文件 C 命令行工具，用于提取 CheatMaker 独立修改器中的工程与配置、读取或移除 CMF 密码，以及解密 CML/CMC 文件。

直接处理文件和 Windows 资源，不需要启动 CheatMaker，也不需要给修改器脱壳。

## 功能

| 命令 | 功能 | 输出 |
| --- | --- | --- |
| `e` | 从 CME 提取 CMF 工程和 CONF 配置 | 指定目录中的 `CMF.cmf`、`CONF.txt` |
| `p` | 读取 CMF 的密码字段 | 打印到终端 |
| `r` | 清空 CMF 的密码字段 | **原地修改输入文件** |
| `d` | 解密 CML/CMC 正文 | 在输入文件名后追加 `.txt` |

CME 指 CheatMaker 生成的独立可执行修改器；CMF 是修改器工程文件；CML 是模拟器列表文件；CMC 是作弊码文件。

## 编译

运行环境为 Windows，使用 GCC/Clang 编译：

```sh
gcc fcm.c -o fcm.exe -lshlwapi
```

仅依赖 C 标准库和 Windows API。程序使用 `assert` 检查文件及资源读取结果，编译时不要添加 `-DNDEBUG`。

## 使用

以下示例在 PowerShell 中执行。

### 提取独立修改器

先创建输出目录，再提取：

```powershell
mkdir extracted
.\fcm.exe e ".\modifier.exe" ".\extracted"
```

生成：

```text
extracted/
├── CMF.cmf
└── CONF.txt
```

- `CMF.cmf`：移除 CME 外层编码后的完整工程文件，正文和附加资源仍保留 CMF 自身的编码。
- `CONF.txt`：解密后的配置文本。

### 读取工程密码

```powershell
.\fcm.exe p ".\extracted\CMF.cmf"
```

打印 `Password: ...`；密码字段为空时打印 `This CMF has no password`。

### 移除工程密码

`r` 会直接改写输入文件。需要保留原文件时先备份：

```powershell
Copy-Item ".\extracted\CMF.cmf" ".\editable.cmf"
.\fcm.exe r ".\editable.cmf"
```

该操作清空正文中的 `passWord=` 字段、更新正文长度，并保留后面的附加资源。

### 解密模拟器列表

```powershell
.\fcm.exe d ".\EmuList.cml"
```

生成 `EmuList.cml.txt`。

## 格式原理

CheatMaker 的这些数据使用循环异或，固定密钥为 27 字节：

```text
/><~F*&2$..*()@#$_+:>?ZXs4Q
```

密码以 `passWord=` 字段明文保存在解密后的工程正文中。

### CMF / CML / CMC

当前命令处理的文件采用新版 24 字节头：

| 偏移 | 长度 | 内容 |
| --- | --- | --- |
| `0x00` | 12 | UTF-16LE BOM 与格式标识+子版本，如 `cmf0b`、`cml04` |
| `0x0C` | 4 | 正文长度，单位为字节，小端序 |
| `0x10` | 4 | 版本值，单精度浮点数 |
| `0x14` | 4 | UTF-16LE CRLF |
| `0x18` | 正文长度 | 编码后的正文 |

文件头不加密；正文按 16 位单元处理：

```c
data[i] ^= cryptkey[i % 27];
```

CMF 正文之后可以附加资源。正文的 `rescount` 和 `[RESn]` 节记录资源的名称、类型及字节长度。资源区解密后的结构为：

```text
资源 1 的原文件字节 | 0D 0A |
资源 2 的原文件字节 | 0D 0A |
……
```

整个资源区按字节连续异或。

### CME

独立修改器通过 PE 资源保存工程和配置：

| 资源类型 / ID | 内容 |
| --- | --- |
| `CMF / 135` | 完整 CMF 文件，额外进行一层逐字节异或 |
| `CONF / 134` | 配置文本，逐 16 位单元异或 |
| `CONF / 144` | 4 字节校验值：`CRC32 + 0x1310FF78` |

校验值的 CRC 覆盖生成过程中、最后写入 `CONF/144` **之前**的整个磁盘文件。
