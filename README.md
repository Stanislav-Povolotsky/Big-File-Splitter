# Big-File-Splitter
This windows tool makes virtual drive, which mirrors user folder and splits big files to smaller chunks just on-fly.  
The tool is useful to backup large files.  
The source code is based on "[Mirror](https://github.com/dokan-dev/dokany/tree/master/samples/dokan_mirror)" sample from [Dokan](https://github.com/dokan-dev/dokany/).  

### Installation:
* [Download](https://github.com/Stanislav-Povolotsky/Big-File-Splitter/releases) right distributive for your OS
* Unpack it and setup dependencies\Dokan_x86|x64.msi
* That's all. Now you can use big-file-splitter.exe

### Video:
![How it works](https://user-images.githubusercontent.com/19610545/43636009-899cf986-9719-11e8-824c-6f56c23ce913.gif)

### Command line examples:

* Mirror C:\Users as RootDirectory in to a drive of letter M:\ and split big files to 100Mb parts
```
big-file-splitter /r C:\Users /l m /z 104857600
```
* Mount as removable drive
```
big-file-splitter /m /r C:\Users /l m
```
* Mount as network drive
```
big-file-splitter /n /r C:\Users /l m
```
* Mount as read only drive
```
big-file-splitter /w /r C:\Users /l m
```
* Enable debug output stderr
```
big-file-splitter /d /s /r C:\Users /l m
```
Note: To unmount the drive, just press CTRL + C in the console.
