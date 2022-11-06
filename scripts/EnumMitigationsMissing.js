/***
 *
 * @kzalloc1(https://github.com/tin-z)
 *
 * Run:
 * .load jsprovider.dll
 * .scriptrun <Path>/EnumMitigationsMissing.js
 *
 * **/


/*** 
 * settings 
 * **/

var DBG = false;
var VRBOSE = false;
var dout = host.diagnostics.debugLog;


// https://github.com/hugsy/windbg_js_scripts/blob/main/scripts/PageExplorer.js
function hex(x){ return x.toString(16); }
function i64(x){ return host.parseInt64(`${x}`); }
function system(x){ return host.namespace.Debugger.Utility.Control.ExecuteCommand(x); }
function ptrsize(){ return host.namespace.Debugger.State.PseudoRegisters.General.ptrsize; }
function pagesize(){ return host.namespace.Debugger.State.PseudoRegisters.General.pagesize; }
function IsX64(){ return ptrsize() === 8;}
function u32(x, k=false){if(!k) return host.memory.readMemoryValues(x, 1, 4)[0];let cmd = `!dd 0x${x.toString(16)}`;let res = system(cmd)[0].split(" ").filter(function(v,i,a){return v.length > 0 && v != "#";});return i64(`0x${res[1].replace("`","")}`);}
function u64(x, k=false){if(!k) return host.memory.readMemoryValues(x, 1, 8)[0];let cmd = `!dq 0x${x.toString(16)}`;let res = system(cmd)[0].split(" ").filter(function(v,i,a){return v.length > 0 && v != "#";});return i64(`0x${res[1].replace("`","")}`);}
function poi(x){ if(IsX64()) return u64(x); else return u32(x);}


function u16(x, k=false){if(!k) return host.memory.readMemoryValues(x, 1, 2)[0];let cmd = `!dw 0x${x.toString(16)}`;let res = system(cmd)[0].split(" ").filter(function(v,i,a){return v.length > 0 && v != "#";});return i64(`0x${res[1].replace("`","")}`);}


/***
 * runtime functions 
 * **/

function initializeScript()
{
    dout("***> Hello World! \n");
}


function invokeScript()
{
  var object = host.namespace.Debugger.Sessions.First().Processes.First().Modules;
  dout("\n[-] Start..\n");

  for (var module of object)
  {
    if (module.Contents == null) {
      if (VRBOSE) {
        dout("Finding headers of module '" + module.Name + "'\n");
      }
      if (! add_headers_manual(module))
      {
        continue;
      }
    }

    var module_obj = new ModuleWrap(module.Name, module.Contents.Headers.FileHeader.Characteristics, module.Contents.Headers.OptionalHeader.DllCharacteristics);
    var str_tmp = module_obj.toString();
    if (VRBOSE) {
      dout(str_tmp);
      dout("\n");
    }
  }

  summary();
  dout("\n[+] Done!\n");
}


function summary()
{
  dout("\n" + "Modules missing mitigations:\n");
  for(var k in dllchars_list) {
    dout("\n" + "  NO-" + dllchars_list[k].id + " : " + missing_dllchars_list[k] + "\n");
  }
}


function add_headers_manual(module)
{
  try {
    var baddr = module.BaseAddress;
    var e_lfanew = poi(baddr + 0x3c);
    var offset_opt_header = baddr + e_lfanew + 0x18;
    var offset_fileheader = baddr + e_lfanew + 0x4;
    var offset_dllchar = offset_opt_header + 0x46;
    var offset_char = offset_fileheader + 0x12;
    var DllCharacteristics = u16(offset_dllchar);
    var Characteristics = u16(offset_char);
    module.Contents = {"Headers":{"OptionalHeader":{"DllCharacteristics":DllCharacteristics}}};
    module.Contents.Headers["FileHeader"] = {"Characteristics": Characteristics};
  } catch (e) {
    dout(e);	
    return false;
  }
  return true;
}


/*** 
 * classes, utils 
 * **/

class DllChars {
  constructor(flg, id, DllCharacteristics, desc){
    this.flg = flg;
    this.id = id;
    this.DllCharacteristics = DllCharacteristics;
    this.desc = desc;
  }
} 

// ref, https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32
var dllchars_list = {
  0x0020 : new DllChars(0x0020, "aslr64", "IMAGE_DLL_CHARACTERISTICS_HIGH_ENTROPY_VA", "ASLR with 64 bit address space.") ,
  0x0040 : new DllChars(0x0040, "aslr", "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE", "The DLL can be relocated at load time.") ,
  0x0080 : new DllChars(0x0080, "signed", "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY", "Forced Integrity checking is a policy that ensures a binary that is being loaded is signed prior to loading.") ,
  0x0100 : new DllChars(0x0100, "dep", "IMAGE_DLLCHARACTERISTICS_NX_COMPAT", "The image is compatible with data execution prevention (DEP).") ,
  0x0400 : new DllChars(0x0400, "noseh", "IMAGE_DLLCHARACTERISTICS_NO_SEH", "The image does not use structured exception handling (SEH). No handlers can be called in this image.") ,
  0x1000 : new DllChars(0x1000, "appcontainer", "IMAGE_DLL_CHARACTERISTICS_APPCONTAINER", "Image should execute in an AppContainer.") ,
  0x4000 : new DllChars(0x4000, "cfg", "IMAGE_DLL_CHARACTERISTICS_GUARD_CF", "Image supports Control Flow Guard.")
};

var missing_dllchars_list = {
    0x0020 : "", 
    0x0040 : "",
    0x0080 : "",
    0x0100 : "",
    0x0400 : "",
    0x1000 : "",
    0x4000 : ""
};

class ModuleWrap {

  constructor(mod_name, mod_characteristics, mod_dllcharacteristics){
    this.mod_name = mod_name; 
    this.mod_characteristics = mod_characteristics; 
    this.mod_dllcharacteristics = mod_dllcharacteristics;
    this.dllchars_flgs = {
      0x0020 : 1, 
      0x0040 : 1,
      0x0080 : 1,
      0x0100 : 1,
      0x0400 : 1,
      0x1000 : 1,
      0x4000 : 1
    };
    this.check();
    this.parsed = false;
  }

  check() {
   for(var k in dllchars_list) {
    this.dllchars_flgs[k] = k & this.mod_dllcharacteristics;
   } 
  }

  toString() {
    var str_tmp = "[+] " + this.mod_name + "\n";

    for(var k in dllchars_list) {

      var dllchars_tmp = dllchars_list[k];
      str_tmp += "  " + dllchars_tmp.id + " : " + ((this.dllchars_flgs[k] ) ? "OK" : "X") + "\n";

      if (! this.dllchars_flgs[k] && ! this.parsed) {
        missing_dllchars_list[k] += "\n" + "    " + this.mod_name;
      }
    } 

    this.parsed = true;
    return str_tmp;
  }

}


