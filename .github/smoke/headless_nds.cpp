#include "NDS.h"
#include "Args.h"
#include "ARM.h"
#include <cstdio>
#include <cstdlib>
#include <memory>

using namespace melonDS;

int main(int argc,char** argv)
{
    int port=argc>1?std::atoi(argv[1]):3333;
    NDSArgs args;
    args.JIT=std::nullopt;
    GDBArgs gdb;
    gdb.PortARM9=(u16)port;
    gdb.PortARM7=0;
    gdb.ARM9BreakOnStartup=true;
    args.GDB=gdb;

    auto nds=std::make_unique<NDS>(std::move(args));
    nds->Reset();

    constexpr u32 base=0x02000000;
    nds->ARM9Write32(base+0x00,0xE3A00001);
    nds->ARM9Write32(base+0x04,0xE2800001);
    nds->ARM9Write32(base+0x08,0xE2800001);
    nds->ARM9Write32(base+0x0C,0xEAFFFFFE);
    nds->ARM9.CPSR=0x1F;
    nds->ARM9.JumpTo(base);
    nds->Start();

    std::fprintf(stderr,"live ARM9 target port=%d base=%08x\n",port,base);
    while(nds->IsRunning())
        nds->RunFrame();
    return 0;
}
