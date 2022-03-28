## Packet Pirate
This is a lightweight **pcap** based network analysis and packet filtering framework for C programming language.

Main features:
1. BPF filtering.
2. Ability to define custom network packet structure.
3. Ability to filter by packet entry/field value.
4. Various packet field data types and their representations.
5. Output as structured database. Supported:
	* MySQL
	* SQLite3
	* PostgreSQL
6. Overridable hooks.
7. Offline analysis mode.
8. Session summary/report.
9. Easy filter addition and deletion.
10.  Noninteractive, thus scriptable product programs
11. Extensive **mconf** configuration interface
12. Builtin tests.
13. Stack of base filters.

### Instalation
In order to fully utilize this frameworks, some dependencies has to be installed:
For **debian** based systems:
```sh
sudo apt update
sudo apt install git gcc make doxygen kconfig-frontends libsqlite3-dev libpcap-dev libmysqlclient-dev libpqxx-dev libcmocka-dev
```
For **arch** based systems:
```sh
sudo pacman -Sy
sudo pacman -S git doxygen base-devel cmocka sqlite3 libpqxx mariadb-libs
# install yay
git clone https://aur.archlinux.org/yay.git
cd yay
sudo makepkg -si
sudo yay -Sy
# install rest of dependencies
yay -S kconfig-frontends
```
There may be differences in package names for other distros.
Due to potental differences in instalation location of dependency header files, you may need to add aditional *include paths* in main *Makefile*.

As this is framework and source code is intended to be seen by dirrect user, thus there is no point in distributing this in binnary form  of some sort. Source code can be downloaded by:
```sh
git clone git@github.com:linper/packet_pirate.git
cd packet_pirate
```
### Generating documentation
```sh
doxygen Doxyfile
```
Documentation in **html** format will be placed in *./docs/* folder.

### Managing filters
All auxilary scripts are contained in *./scripts/* directory. They are intended to be used from one centralized script *./scripts/manage.sh*. It's usage looks like this:
```
Usage: [options ...] <command> <target> [params ...]
Commands:
	delete          Deletes stuff
	new	            Creates stuff
	update          Updates stuff
Target:
	filter          Only network filters (for now)
Options:
	-h|--help       Display this message
```
As you see *command* describes action. *Target* descirbes subject on which action will be taken. Currently there is only one possible target - *filter*. In addition you can pass *parameters*, but they differ for each *target-command* pair.

#### Creating filter
If you want to create new filter you have to execte:
```sh
./scripts/manage.sh new filter -n "<new filter name>" -p "<parent filter name>"
```
**-n** or **--name** option is mandatory. It passes new filter's name. While **-p** or **--parent** is optional. It shows hierarchicly highier filter. If this option is missing then this option will become child of root filter, i. e. like *ethernet* filter.
If command is executed correctly, then new filter's files will be placed in *./src/filters/\<filter name\>/* folder. It creates filter with superfluous functions for full display of functionality.
#### Deleting filter
This is similar to filter creation. This time you have to execte:
```sh
./scripts/manage.sh delete filter -n "<filter name>"
```
This has one main mandatory option - **-n** or **--name**. This option tells which filter has to be removed.
#### Updating filters
This command updates your project if some filters ware created or deleted manually. This command has no parameters. Command:
```sh
./scripts/manage.sh update filter
```
### Compilation system
Compilation system usage is described by its *help* message below.  You have run it while being in project root directory.
```
Usage: make [options]
Options:
    [none] | all    Cleans and builds project
    clean           Cleans compiled binaries and temporary data
    compile         Builds project
    help            Displays this message
    menuconfig      Opens 'mconf' based configuration TUI
    run             Runs built project(for development purposes)
    test            Runs auto tests
```
### Product usage
Software developed by this framework by default are not interactive command line tools with their usage described in their self explanatory *help* message:
```
Usage: pp [OPTION...]
Powered by 'Packet Pirate' sniffing framework in C

  -b, --bpf=query               BPF program, with full support. If given, overrides all filters above
  -d, --device=device           Interface/device to sniff
  -g, --grow=filter             Allows modifications of filter tree. Filter tree node to grow branch to. Works with 'prune' parameter. Can use multiple times
  -p, --prune=filter            Allows modifications of filter tree. Filter tree branch to prune. Works with 'grow' parameter. Can use multiple times
  -s, --sample=file             Sample .pcap file for offline analysis
  -v, --verbose=verbosity       Set verbosity [0-6]
  -?, --help                    Give this help list
      --usage                   Give a short usage message
  -V, --version                 Print program version

Mandatory or optional arguments to long options are also mandatory or optional
for any corresponding short options.
```
### Development
Nearly all relevant information about new filter development is contained in *filter.h* and *utils.h* header files. They contain descriptions of structures, functions and macros that are relevant to user filters. You can check them out in **Doxygen** generated documentation or directly in source code.
You can also use base filters as a sample. They contain working filters for certain network protocols.
Finaly, newly careated filter lots of superfluous logic that you can adapt to your needs.


