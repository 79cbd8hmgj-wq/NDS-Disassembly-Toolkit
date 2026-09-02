#include "Platform.h"
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <dlfcn.h>
#include <sys/stat.h>

namespace melonDS::Platform {
struct FileHandle { FILE* f; };
struct Thread { std::thread t; explicit Thread(std::function<void()> fn): t(std::move(fn)) {} };
struct Semaphore { std::mutex m; std::condition_variable cv; int count=0; };
struct Mutex { std::mutex m; };
struct AACDecoder {};
struct DynamicLibrary { void* h=nullptr; };
void SignalStop(StopReason, void*) {}
std::string GetLocalFilePath(const std::string& filename){ return filename; }
static const char* mode_to_c(FileMode mode){
    bool r=(mode&Read)==Read, w=(mode&Write)==Write, append=(mode&Append)==Append;
    bool preserve=(mode&Preserve)==Preserve, text=(mode&Text)==Text;
    if(append) return r?(text?"a+":"a+b"):(text?"a":"ab");
    if(r&&w) return preserve?(text?"r+":"r+b"):(text?"w+":"w+b");
    if(w) return text?"w":"wb";
    return text?"r":"rb";
}
FileHandle* OpenFile(const std::string& path, FileMode mode){ FILE* f=std::fopen(path.c_str(),mode_to_c(mode)); return f?new FileHandle{f}:nullptr; }
FileHandle* OpenLocalFile(const std::string& path, FileMode mode){ return OpenFile(path,mode); }
bool FileExists(const std::string& name){ struct stat st{}; return stat(name.c_str(),&st)==0; }
bool LocalFileExists(const std::string& name){ return FileExists(name); }
bool CheckFileWritable(const std::string& p){ FILE* f=std::fopen(p.c_str(),"ab"); if(!f)return false; std::fclose(f); return true; }
bool CheckLocalFileWritable(const std::string& p){ return CheckFileWritable(p); }
bool CloseFile(FileHandle* f){ if(!f)return false; bool ok=std::fclose(f->f)==0; delete f; return ok; }
bool IsEndOfFile(FileHandle* f){ return !f||std::feof(f->f); }
bool FileReadLine(char* s,int n,FileHandle* f){ return f&&std::fgets(s,n,f->f); }
u64 FilePosition(FileHandle* f){ if(!f)return 0; long p=std::ftell(f->f); return p<0?0:(u64)p; }
bool FileSeek(FileHandle* f,s64 off,FileSeekOrigin o){ if(!f)return false; int w=o==FileSeekOrigin::Start?SEEK_SET:(o==FileSeekOrigin::Current?SEEK_CUR:SEEK_END); return std::fseek(f->f,(long)off,w)==0; }
void FileRewind(FileHandle* f){ if(f)std::rewind(f->f); }
u64 FileRead(void* d,u64 s,u64 c,FileHandle* f){ return f?std::fread(d,(size_t)s,(size_t)c,f->f):0; }
bool FileFlush(FileHandle* f){ return f&&std::fflush(f->f)==0; }
u64 FileWrite(const void* d,u64 s,u64 c,FileHandle* f){ return f?std::fwrite(d,(size_t)s,(size_t)c,f->f):0; }
u64 FileWriteFormatted(FileHandle* f,const char* fmt,...){ if(!f)return 0; va_list ap; va_start(ap,fmt); int n=std::vfprintf(f->f,fmt,ap); va_end(ap); return n<0?0:(u64)n; }
u64 FileLength(FileHandle* f){ if(!f)return 0; long old=std::ftell(f->f); if(old<0)return 0; if(std::fseek(f->f,0,SEEK_END))return 0; long end=std::ftell(f->f); std::fseek(f->f,old,SEEK_SET); return end<0?0:(u64)end; }
void Log(LogLevel level,const char* fmt,...){ const char* p=level==Error?"ERR":level==Warn?"WRN":level==Info?"INF":"DBG"; std::fprintf(stderr,"[%s] ",p); va_list ap; va_start(ap,fmt); std::vfprintf(stderr,fmt,ap); va_end(ap); }
Thread* Thread_Create(std::function<void()> fn){ return new Thread(std::move(fn)); }
void Thread_Free(Thread* t){ if(!t)return; if(t->t.joinable())t->t.detach(); delete t; }
void Thread_Wait(Thread* t){ if(t&&t->t.joinable())t->t.join(); }
Semaphore* Semaphore_Create(){ return new Semaphore; }
void Semaphore_Free(Semaphore* s){ delete s; }
void Semaphore_Reset(Semaphore* s){ if(!s)return; std::lock_guard<std::mutex> l(s->m); s->count=0; }
void Semaphore_Wait(Semaphore* s){ std::unique_lock<std::mutex> l(s->m); s->cv.wait(l,[&]{return s->count>0;}); --s->count; }
bool Semaphore_TryWait(Semaphore* s,int ms){ std::unique_lock<std::mutex> l(s->m); if(ms==0){if(s->count<=0)return false;} else if(!s->cv.wait_for(l,std::chrono::milliseconds(ms),[&]{return s->count>0;}))return false; --s->count; return true; }
void Semaphore_Post(Semaphore* s,int count){ {std::lock_guard<std::mutex> l(s->m); s->count+=count;} s->cv.notify_all(); }
Mutex* Mutex_Create(){ return new Mutex; }
void Mutex_Free(Mutex* m){delete m;}
void Mutex_Lock(Mutex* m){m->m.lock();}
void Mutex_Unlock(Mutex* m){m->m.unlock();}
bool Mutex_TryLock(Mutex* m){return m->m.try_lock();}
void Sleep(u64 us){std::this_thread::sleep_for(std::chrono::microseconds(us));}
u64 GetMSCount(){return (u64)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();}
u64 GetUSCount(){return (u64)std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();}
void WriteNDSSave(const u8*,u32,u32,u32,void*){}
void WriteGBASave(const u8*,u32,u32,u32,void*){}
void WriteFirmware(const Firmware&,u32,u32,void*){}
void WriteDateTime(int,int,int,int,int,int,void*){}
void MP_Begin(void*){}
void MP_End(void*){}
int MP_SendPacket(u8*,int n,u64,void*){return n;}
int MP_RecvPacket(u8*,u64*,void*){return 0;}
int MP_SendCmd(u8*,int n,u64,void*){return n;}
int MP_SendReply(u8*,int n,u64,u16,void*){return n;}
int MP_SendAck(u8*,int n,u64,void*){return n;}
int MP_RecvHostPacket(u8*,u64*,void*){return 0;}
u16 MP_RecvReplies(u8*,u64,u16,void*){return 0;}
int Net_SendPacket(u8*,int n,void*){return n;}
int Net_RecvPacket(u8*,void*){return 0;}
void Camera_Start(int,void*){}
void Camera_Stop(int,void*){}
void Camera_CaptureFrame(int,u32* f,int w,int h,bool,void*){if(f)std::memset(f,0,(size_t)w*h*sizeof(u32));}
void Mic_Start(void*){}
void Mic_Stop(void*){}
int Mic_ReadInput(s16* d,int n,void*){if(d)std::memset(d,0,(size_t)n*sizeof(s16)); return n;}
AACDecoder* AAC_Init(){return nullptr;}
void AAC_DeInit(AACDecoder*){}
bool AAC_Configure(AACDecoder*,int,int){return false;}
bool AAC_DecodeFrame(AACDecoder*,const void*,int,void*,int){return false;}
bool Addon_KeyDown(KeyType,void*){return false;}
void Addon_RumbleStart(u32,void*){}
void Addon_RumbleStop(void*){}
float Addon_MotionQuery(MotionQueryType,void*){return 0.0f;}
DynamicLibrary* DynamicLibrary_Load(const char* lib){void* h=dlopen(lib,RTLD_LAZY); return h?new DynamicLibrary{h}:nullptr;}
void DynamicLibrary_Unload(DynamicLibrary* l){if(!l)return;if(l->h)dlclose(l->h);delete l;}
void* DynamicLibrary_LoadFunction(DynamicLibrary* l,const char* n){return l&&l->h?dlsym(l->h,n):nullptr;}
}
