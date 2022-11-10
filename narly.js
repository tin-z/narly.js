/***
 *
 * Altin (tin-z)
 * https://github.com/tin-z
 *
 * Run on windbg:
 * .load jsprovider.dll
 * .scriptload <Path>/narly.js
 *
 *
 * Example usage:
 * !nmod "--help"
 * !nmod "--info"
 * !nmod "--missing"
 * !nmod
 * !nmod "<module-name>"
 * **/


/*** 
 * settings 
 * **/
var dout = host.diagnostics.debugLog;

var narly_logo =
"      __s|I}*!{a.                        ._s,aan2*a" + "\n" +
"     _wY1+~-    )S,                     .ae\"~=:...:X" + "\n" +
"   .vXl+:.       -4c                   <2+=|==::..:d" + "\n" +
"   vvi=;..        -?o,                =2=+==:::...=d" + "\n" +
"  )nv=:.            )5,              .2=--.......-=d" + "\n" +
"  ue+::              -*s             <c .        .=d" + "\n" +
"  m>==::..     ._,     <s,           )c           :d" + "\n" +
"  #==viii|===; {Xs=,    -{s          )c         ..:d" + "\n" +
"  Z;{nnonnvvii;v(-{%=.    ~s,        )e:====||iiv%=d" + "\n" +
"  X={oooonvvIl;3;  -{%,    -*>       )2<onnnnvnnnn>d" + "\n" +
"  X=)vvvvIliii:3;    -!s.   :)s.     )e<oonvlllllIid" + "\n" +
"  X=<lllliii|=:n;      -1c.  +|1,    )z<nvii||+|+|vX" + "\n" +
"  S=<lli|||=:: n;        \"nc  -s%;   )c=ovl|++==+=vo" + "\n" +
"  X=<i||+=; . .n`          \"1>.-{%i. )c<Xnnli||++=vn" + "\n" +
"  X=iii>==-.  :o`            \"1,:+iI,)c:Sonnvli||=v(" + "\n" +
"  X>{ii+;:-  .u(               \"o,-{Iw(:nvvvllii=v2" + "\n" +
"  S=i||;:. .=u(                 -!o,+I(:iiillii|ie`" + "\n" +
"  2>v|==__su?`                    -?o,-:==||iisv\"" + "\n" +
"  {nvnI!\"\"~                         -!sasvv}\"\"`.JS" + "\n" ;

var brief_desc = 
"  narly.js - Print binary protections using windbg JS API." + "\n" +
"	The name \"narly\" has been borrowed from the famous windbg extension narly" + "\n" +
"	which was developed by \"Nephi Johnson (d0c_s4vage)\" and is available at:" + "\n" +
"	https://code.google.com/archive/p/narly/" + "\n";


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
function hex_out(x){ return Number(x).toString(16).padStart(8, "0"); }


/***
 * runtime functions 
 * **/

function initializeScript()
{
  dout("***> Hello World! \n");
}


var already_eval = false;
var module_parsed = {};

function main(mod_name_arg, print_missing_list)
{
  var object = host.namespace.Debugger.Sessions.First().Processes.First().Modules;

  var IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10;  
  var SecurityCookie_offset = 60;
  var SEHandlerTable_offset = SecurityCookie_offset + 4;

  if (IsX64()) {
    SecurityCookie_offset = 88;
    SEHandlerTable_offset = SecurityCookie_offset + 8;
  }

  if (!already_eval) {
    dout("\n[-] Start..\n");

    for (var module of object) {
      // for testing
      // delete module.Contents;
      
      if (module.Contents == null) {
        if (! add_headers_manual(module))
        {
          dout("[!] Some issue parsing '" + module.Name + "' ..skipping it\n");
          continue;
        }
      }

      var baddr = module.BaseAddress;
      var eaddr = baddr + module.Size;
      var path_name = module.Name;
      var tmplist = path_name.split("\\");
      var name = tmplist[tmplist.length-1];
      
      var charact = module.Contents.Headers.FileHeader.Characteristics;
      var dll_char = module.Contents.Headers.OptionalHeader.DllCharacteristics;

      var gs_is_present = false;
      var safeseh_is_present = false;
      var dirs = module.Contents.Headers.OptionalHeader.DataDirectory;

      if (dirs.length > 10) {
        var gs_vaddr = dirs[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;

        if (gs_vaddr > 0) {
          var SecurityCookie = poi(gs_vaddr + baddr + SecurityCookie_offset);
          var SEHandlerTable = poi(gs_vaddr + baddr + SEHandlerTable_offset);

          if (SecurityCookie != 0) {
            gs_is_present = true;
          }
          if (SEHandlerTable != 0) {
            safeseh_is_present = true;
          }				
        }
      }

      var module_obj = new ModuleWrap(baddr, eaddr, name, path_name, charact, dll_char, gs_is_present, safeseh_is_present);
      module_parsed[name] = module_obj;
      module_parsed[path_name] = module_obj;
      var str_tmp = module_obj.toString();
    }

    already_eval = true;
    dout("\n[+] Done!\n");
  }

  if (print_missing_list) {
    summary();
  } else {
    print_narly_format(mod_name_arg);
  }
}


function summary()
{
  dout("\n" + "Modules missing mitigations:\n");
  for(var k in dllchars_list) {
    dout("\n" + "  NO-" + dllchars_list[k].id + " : " + missing_dllchars_list[k] + "\n");
  }
  dout("\n" + "  NO-GS : " + missing_dllchars_list["/GS"] + "\n");
  dout("\n" + "  NO-SafeSEH : " + missing_dllchars_list["/SafeSEH"] + "\n");
  dout("\n");
}

function print_narly_format(mod_name_arg)
{
  if (mod_name_arg != ""){

    if (!(mod_name_arg in module_parsed)) {
      dout("[X] Can't find the module-name given: '" + mod_name_arg + "'\n\n");

    } else {
      dout(module_parsed[mod_name_arg].toString() + "\n");
    }
  } else {

    for(var k in module_parsed) {
	    dout(module_parsed[k].toString());
	  }
	  dout("\n");
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
    module.Contents.Headers.OptionalHeader["DataDirectory"] = [0,0,0,0,0,0,0,0,0,0];

	  // fix /GS and /SafeSEH check
	  var offset_number_of_rva_and_size = baddr + e_lfanew + 0x74;	
	  var number_of_rva_and_size = u32(offset_number_of_rva_and_size);
	  if (number_of_rva_and_size > 0xa) {
	    var va_load_config = poi(offset_number_of_rva_and_size + (4*10));
	    module.Contents.Headers.OptionalHeader.DataDirectory[0xa]={"VirtualAddress":va_load_config};
	  }

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
  0x0020 : new DllChars(0x0020, "*ASLR64", "IMAGE_DLL_CHARACTERISTICS_HIGH_ENTROPY_VA", "ASLR with 64 bit address space.") ,
  0x0040 : new DllChars(0x0040, "*ASLR", "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE", "The DLL can be relocated at load time.") ,
  0x0080 : new DllChars(0x0080, "SIGNED", "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY", "Forced Integrity checking is a policy that ensures a binary that is being loaded is signed prior to loading.") ,
  0x0100 : new DllChars(0x0100, "*DEP", "IMAGE_DLLCHARACTERISTICS_NX_COMPAT", "The image is compatible with data execution prevention (DEP).") ,
  0x0400 : new DllChars(0x0400, "NOSEH", "IMAGE_DLLCHARACTERISTICS_NO_SEH", "The image does not use structured exception handling (SEH). No handlers can be called in this image.") ,
  0x1000 : new DllChars(0x1000, "APPCONTAINER", "IMAGE_DLL_CHARACTERISTICS_APPCONTAINER", "Image should execute in an AppContainer.") ,
  0x4000 : new DllChars(0x4000, "CFG_GUARD", "IMAGE_DLL_CHARACTERISTICS_GUARD_CF", "Image supports Control Flow Guard.")
};

var missing_dllchars_list = {
  0x0020 : "", 
  0x0040 : "",
  0x0080 : "",
  0x0100 : "",
  0x0400 : "",
  0x1000 : "",
  0x4000 : "",
  "/GS" : "",
  "/SafeSEH" : ""
};

class ModuleWrap {

  constructor(mod_baddr, mod_eaddr, mod_name, path_name, mod_characteristics, mod_dllcharacteristics, gs_is_present, safeseh_is_present){
    this.baddr = mod_baddr;
    this.eaddr = mod_eaddr;
    this.mod_name = mod_name;
    this.path_name = path_name;
    this.mod_characteristics = mod_characteristics; 
    this.mod_dllcharacteristics = mod_dllcharacteristics;
    this.gs_is_present = gs_is_present;
    this.safeseh_is_present = safeseh_is_present;	
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
    var str_tmp = hex_out(this.baddr) + " " + hex_out(this.eaddr) + " " + this.mod_name.padEnd(16, " ");
    str_tmp += " (" + this.path_name + ")\n";
    
    str_tmp += "/SafeSEH:" + ((this.safeseh_is_present ) ? "OK" : "X") + "  ";
    str_tmp += "/GS:" + ((this.gs_is_present ) ? "OK" : "X") + "  ";
    
    for(var k in dllchars_list) {
      var dllchars_tmp = dllchars_list[k];
      str_tmp += dllchars_tmp.id + ":" + ((this.dllchars_flgs[k] ) ? "OK" : "X") + "  ";
    
      if (! this.dllchars_flgs[k] && ! this.parsed) {
        missing_dllchars_list[k] += "\n" + "    " + this.path_name;
      }
    }
  
    if (! this.parsed) {
      if (! this.gs_is_present)
        missing_dllchars_list["/GS"] += "\n" + "    " + this.path_name;
      if (! this.safeseh_is_present)
        missing_dllchars_list["/SafeSEH"] += "\n" + "    " + this.path_name;
    }
  
    str_tmp += "\n\n";
    this.parsed = true;
    return str_tmp;
  }
}

function __helper() {
  var output =
	"" + "\n" +
	"Name:" + "\n" +
	"		narly.js - print binary protections. in order: /SafeSEH /GS ASLR DEP NOSEH CFG_GUARD APPCONTAINER SIGNED" + "\n" +
	"Usage:" + "\n" +
	"		!nmod [\"--help\"|\"--info\"|\"--missing\"|\"<module-name>\"]" + "\n" +
	"" + "\n" +
	"Options:" + "\n" +
	"		\"--help\"	: print this message" + "\n" +
	"		\"--info\"	: print information regarding the binary protections printed out" + "\n" +
	"		\"--missing\"	: print also binary/modules missing binary protections, instead of printing each module and its binary protections" + "\n" +
	"		\"<module-name>	: print module-name's binary protections" + "\n" ;
	dout(output + "\n");
}

function __print_info() {
	dout("#TODO: function __print_info\n");
}


function __Narly(option_sel)
{
	if(option_sel){
		option_sel = option_sel.toString(16).trim();
	} else {
		option_sel = "";
	}
	
	dout("\n");
	
	if (option_sel == "--help") {
		return __helper();
	} else if(option_sel == "--info") {
		return __print_info();
	} else {
		return main(option_sel, option_sel == "--missing");
	}
}


function initializeScript()
{
  dout("\n" + narly_logo);
  dout("\n" + brief_desc);
  __helper();
  
  return [new host.apiVersionSupport(1, 0),
          new host.functionAlias(__Narly, "nmod")];
}

