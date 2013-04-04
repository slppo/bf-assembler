#include <Windows.h>
#include <string>
#include <stack>
#include <memory>
#include <iostream>
#include <fstream>
#include <cassert>

const char *StdLib =
#ifndef NDEBUG
  "msvcr110d.dll";
#else
  "msvcr110.dll";
#endif

typedef void (*bf_fn)();

const std::size_t BufferSize = 16384;

class BrainFucktor
{
public:
  BrainFucktor(bf_fn func, DWORD oldProtection) : _func(func), 
    _oldProtection(oldProtection) { }
  ~BrainFucktor() 
  { 
    DWORD old;
    VirtualProtect(_func, BufferSize, _oldProtection, &old);
    delete reinterpret_cast<void*>(_func); 
    _func = nullptr; 
  }
  void operator()() { _func(); }
private:
  bf_fn _func;
  DWORD _oldProtection;
};

BrainFucktor Compile(const std::string &code);
std::string BrainfuckIgnore(const std::string &code);

int main(int argc, const char **argv)
{    
  std::istream *is = nullptr;
  if(argc > 0)
    is = new std::ifstream(argv[1]);
  else
    is = &std::cin;

  if(!*is)
    return 1;

  std::string code;
  std::copy(std::istreambuf_iterator<char>(*is),
    std::istreambuf_iterator<char>(), std::back_inserter(code));

  if(is != &std::cin)
    delete is;

  BrainFucktor func = Compile(code);    
  std::cout << "Executing function...\n";
  func();  
  std::cout << "...complete\n";

  std::cin.get();
  return 0;  
}

BrainFucktor Compile(const std::string &code)
{
  std::string cleanedCode = BrainfuckIgnore(code);

  UINT_PTR memsetProc = reinterpret_cast<UINT_PTR>(GetProcAddress(
    GetModuleHandle(StdLib), "memset"));
  UINT_PTR putcharProc = reinterpret_cast<UINT_PTR>(GetProcAddress(
    GetModuleHandle(StdLib), "putchar"));
  UINT_PTR getcharProc = reinterpret_cast<UINT_PTR>(GetProcAddress(
    GetModuleHandle(StdLib), "getchar"));

  void *buffer = operator new(BufferSize);
  unsigned char *walker = reinterpret_cast<unsigned char*>(buffer);
  std::size_t idx = 0;

#define OP(opcode) walker[idx++] = opcode
  // PROLOG
  OP(0x55); // push ebp
  OP(0x89); OP(0xE5); // mov ebp, esp  
  OP(0x81); OP(0xEC); OP(0x90); OP(0x0C); OP(0x00); OP(0x00); // sub esp, 0xc90  
  OP(0x8D); OP(0x85); OP(0x40); OP(0xF4); OP(0xFF); OP(0xFF); // lea eax, [ebp-0xbc0]
  OP(0x89); OP(0x85); OP(0x34); OP(0xF4); OP(0xFF); OP(0xFF); // mov dword ptr [ebp-0xbcc], eax

  OP(0xc6); OP(0x85); OP(0x44); OP(0xff); OP(0xff); OP(0xff); OP(0x00); // mov byte ptr [ebp-0xbc], 0
  OP(0x68); OP(0xb7); OP(0x0b); OP(0x00); OP(0x00); // push 0xbb7
  OP(0x6a); OP(0x00); // push 0
  OP(0x8D); OP(0x85); OP(0x41); OP(0xF4); OP(0xFF); OP(0xFF); // lea eax, [ebp-0xbbf]
  OP(0x48); // dec eax
  OP(0x50); // push eax
  OP(0xe8); 
  
  UINT_PTR memsetLoc = (memsetProc - reinterpret_cast<UINT_PTR>(buffer)) - idx - 0x04;

  OP(LOBYTE(LOWORD(memsetLoc))); OP(HIBYTE(LOWORD(memsetLoc))); 
  OP(LOBYTE(HIWORD(memsetLoc))); OP(HIBYTE(HIWORD(memsetLoc))); // call memset
  OP(0x83); OP(0xc4); OP(0x0c); // add esp, 0x0c    
  // PROLOG

  std::stack<std::pair<unsigned int*, std::size_t>> loops;

  for(char ch : cleanedCode)
  {
    switch(ch)
    {
    case '+':
      OP(0x8B); OP(0x85); OP(0x34); OP(0xF4); OP(0xFF); OP(0xFF); // mov eax, dword ptr [ebp-0xbcc]
      OP(0x8A); OP(0x08); // mov cl, byte ptr [eax]
      OP(0xFE); OP(0xC1); // inc cl
      OP(0x8B); OP(0x95); OP(0x34); OP(0xF4); OP(0xFF); OP(0xFF); // mov edx, dword ptr [ebp-0xbcc]
      OP(0x88); OP(0x0A); // mov byte ptr [edx], cl
      break;
    case '-':
      OP(0x8B); OP(0x85); OP(0x34); OP(0xF4); OP(0xFF); OP(0xFF); // mov eax, dword ptr [ebp-0xbcc]
      OP(0x8A); OP(0x08); // mov cl, byte ptr [eax]
      OP(0xFE); OP(0xC9); // dec cl
      OP(0x8B); OP(0x95); OP(0x34); OP(0xF4); OP(0xFF); OP(0xFF); // mov edx, dword ptr [ebp-0xbcc]
      OP(0x88); OP(0x0A); // mov byte ptr [edx], cl
      break;
    case '>':
      OP(0x8B); OP(0x85); OP(0x34); OP(0xF4); OP(0xFF); OP(0xFF); // mov eax, dword ptr [ebp-0xbcc]
      OP(0x40); // inc eax
      OP(0x89); OP(0x85); OP(0x34); OP(0xF4); OP(0xFF); OP(0xFF); // mov dword ptr [ebp-0xbcc], eax
      break;
    case '<':
      OP(0x8B); OP(0x85); OP(0x34); OP(0xF4); OP(0xFF); OP(0xFF); // mov eax, dword ptr [ebp-0xbcc]
      OP(0x48); // dec eax
      OP(0x89); OP(0x85); OP(0x34); OP(0xF4); OP(0xFF); OP(0xFF); // mov dword ptr [ebp-0xbcc], eax
      break;
    case '.':
      {
      OP(0x8B); OP(0x85); OP(0x34); OP(0xF4); OP(0xFF); OP(0xFF); // mov eax, dword ptr [ebp-0xbcc]
      OP(0x0f); OP(0xbe); OP(0x08); // movsx ecx, byte ptr [eax]
      OP(0x51); // push ecx

      OP(0xe8);
      UINT_PTR putcharLoc = (putcharProc - reinterpret_cast<UINT_PTR>(buffer)) - idx - 0x04;

      OP(LOBYTE(LOWORD(putcharLoc))); OP(HIBYTE(LOWORD(putcharLoc))); 
      OP(LOBYTE(HIWORD(putcharLoc))); OP(HIBYTE(HIWORD(putcharLoc))); // call putchar

      OP(0x83); OP(0xc4); OP(0x04); // add esp, 4

      OP(0x8B); OP(0x85); OP(0x34); OP(0xF4); OP(0xFF); OP(0xFF); // mov eax, dword ptr [ebp-0xbcc]
      }
      break;
    case ',':
      {
      OP(0xe8);      
      UINT_PTR getcharLoc = (getcharProc - reinterpret_cast<UINT_PTR>(buffer)) - idx - 0x04;      

      OP(LOBYTE(LOWORD(getcharLoc))); OP(HIBYTE(LOWORD(getcharLoc))); 
      OP(LOBYTE(HIWORD(getcharLoc))); OP(HIBYTE(HIWORD(getcharLoc))); // call getchar
      OP(0x8B); OP(0x8d); OP(0x34); OP(0xf4); OP(0xff); OP(0xff); // mov ecx, dword ptr [ebp-0xbcc]
      OP(0x88); OP(0x01); // mov byte ptr [ecx], al
      OP(0x8B); OP(0x85); OP(0x34); OP(0xF4); OP(0xFF); OP(0xFF); // mov eax, dword ptr [ebp-0xbcc]
      }
      break;
    case '[':            
      {
      unsigned int *endLoop = 0;
      std::pair<unsigned int*, std::size_t> pair(endLoop, idx);
      OP(0x8B); OP(0x8d); OP(0x34); OP(0xf4); OP(0xff); OP(0xff); // mov ecx, dword ptr [ebp-0xbcc]
      OP(0x0f); OP(0xbe); OP(0x08); // movsx ecx, byte ptr [eax]      
      OP(0x85); OP(0xc9); // test ecx, ecx
      OP(0x0f); OP(0x84); OP(0x00); OP(0x00); OP(0x00); OP(0x00); // je short ]
      pair.first = reinterpret_cast<unsigned int*>(&walker[idx-4]);
      loops.push(pair);
      }
      break;
    case ']':
      {
      std::pair<unsigned int*, std::size_t> pair = loops.top();
      loops.pop();
      unsigned int offset = 0xFFFFFFFF - (idx - pair.second) - 4;
      OP(0xe9); OP(LOBYTE(LOWORD(offset))); OP(HIBYTE(LOWORD(offset))); OP(LOBYTE(HIWORD(offset)));
        OP(HIBYTE(HIWORD(offset))); // jmp short [
      *pair.first = static_cast<unsigned int>(idx - pair.second) - 17;
      }
      break;
    default: assert(0);
    }
  }

  // EPILOG
  OP(0x89); 
  OP(0xEC); // mov esp, ebp
  OP(0x5D); // pop ebp
  OP(0xC3); // ret
  // EPILOG
#undef OP

  DWORD old;
  VirtualProtect(buffer, BufferSize, PAGE_EXECUTE_READWRITE, &old);
  return BrainFucktor(reinterpret_cast<bf_fn>(buffer), old);
}

std::string BrainfuckIgnore(const std::string &code)
{
  std::string result;
  for(char ch : code)
    if(ch == '+' || ch == '-' || ch == '>' || ch == '<' || ch == '[' || ch == ']' || ch == ',' || ch == '.')
      result += ch;
  return result;
}