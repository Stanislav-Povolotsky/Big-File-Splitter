# Big-File-Splitter
This tool makes virtual drive, which mirrors user folder and splits big files to smaller chunks just on-fly.  
Tool is useful to backup large files.  
Source code is based on "[Mirror](https://github.com/dokan-dev/dokany/tree/master/samples/dokan_mirror)" sample from [Dokan](https://github.com/dokan-dev/dokany/).  

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
