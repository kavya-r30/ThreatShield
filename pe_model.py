import pefile
import os
import array
import math
import pickle
import joblib
import sys
import argparse

def get_entropy(data):
    if len(data) == 0:
        return 0.0
    occurences = array.array('L', [0]*256)
    for x in data:
        occurences[x if isinstance(x, int) else ord(x)] += 1

    entropy = 0
    for x in occurences:
        if x:
            p_x = float(x) / len(data)
            entropy -= p_x*math.log(p_x, 2)

    return entropy

def get_resources(pe):
    """Extract resources :
    [entropy, size]"""
    resources = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        try:
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                size = resource_lang.data.struct.Size
                                entropy = get_entropy(data)

                                resources.append([entropy, size])
        except Exception as e:
            return resources
    return resources

def get_version_info(pe):
    """Return version infos"""
    res = {}
    for fileinfo in pe.FileInfo:
        if fileinfo.Key == 'StringFileInfo':
            for st in fileinfo.StringTable:
                for entry in st.entries.items():
                    res[entry[0]] = entry[1]
        if fileinfo.Key == 'VarFileInfo':
            for var in fileinfo.Var:
                res[var.entry.items()[0][0]] = var.entry.items()[0][1]
    if hasattr(pe, 'VS_FIXEDFILEINFO'):
          res['flags'] = pe.VS_FIXEDFILEINFO.FileFlags
          res['os'] = pe.VS_FIXEDFILEINFO.FileOS
          res['type'] = pe.VS_FIXEDFILEINFO.FileType
          res['file_version'] = pe.VS_FIXEDFILEINFO.FileVersionLS
          res['product_version'] = pe.VS_FIXEDFILEINFO.ProductVersionLS
          res['signature'] = pe.VS_FIXEDFILEINFO.Signature
          res['struct_version'] = pe.VS_FIXEDFILEINFO.StrucVersion
    return res

def extract_infos(fpath):
    res = {}
    pe = pefile.PE(fpath)
    res['Machine'] = pe.FILE_HEADER.Machine
    res['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
    res['Characteristics'] = pe.FILE_HEADER.Characteristics
    res['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
    res['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
    res['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
    res['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
    res['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
    res['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    res['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
    try:
        res['BaseOfData'] = pe.OPTIONAL_HEADER.BaseOfData
    except AttributeError:
        res['BaseOfData'] = 0
    res['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
    res['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
    res['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
    res['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
    res['MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
    res['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
    res['MinorImageVersion'] = pe.OPTIONAL_HEADER.MinorImageVersion
    res['MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
    res['MinorSubsystemVersion'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
    res['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
    res['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
    res['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
    res['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
    res['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
    res['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
    res['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
    res['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
    res['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
    res['LoaderFlags'] = pe.OPTIONAL_HEADER.LoaderFlags
    res['NumberOfRvaAndSizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes

    res['SectionsNb'] = len(pe.sections)
    entropy = list(map(lambda x:x.get_entropy(), pe.sections))
    res['SectionsMeanEntropy'] = sum(entropy)/float(len((entropy)))
    res['SectionsMinEntropy'] = min(entropy)
    res['SectionsMaxEntropy'] = max(entropy)
    raw_sizes = list(map(lambda x:x.SizeOfRawData, pe.sections))
    res['SectionsMeanRawsize'] = sum(raw_sizes)/float(len((raw_sizes)))
    res['SectionsMinRawsize'] = min(raw_sizes)
    res['SectionsMaxRawsize'] = max(raw_sizes)
    virtual_sizes = list(map(lambda x:x.Misc_VirtualSize, pe.sections))
    res['SectionsMeanVirtualsize'] = sum(virtual_sizes)/float(len(virtual_sizes))
    res['SectionsMinVirtualsize'] = min(virtual_sizes)
    res['SectionMaxVirtualsize'] = max(virtual_sizes)

    try:
        res['ImportsNbDLL'] = len(pe.DIRECTORY_ENTRY_IMPORT)
        imports = sum([x.imports for x in pe.DIRECTORY_ENTRY_IMPORT], [])
        res['ImportsNb'] = len(imports)
        res['ImportsNbOrdinal'] = 0
    except AttributeError:
        res['ImportsNbDLL'] = 0
        res['ImportsNb'] = 0
        res['ImportsNbOrdinal'] = 0

    try:
        res['ExportNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
    except AttributeError:
        res['ExportNb'] = 0
    resources= get_resources(pe)
    res['ResourcesNb'] = len(resources)
    if len(resources)> 0:
        entropy = list(map(lambda x:x[0], resources))
        res['ResourcesMeanEntropy'] = sum(entropy)/float(len(entropy))
        res['ResourcesMinEntropy'] = min(entropy)
        res['ResourcesMaxEntropy'] = max(entropy)
        sizes = list(map(lambda x:x[1], resources))
        res['ResourcesMeanSize'] = sum(sizes)/float(len(sizes))
        res['ResourcesMinSize'] = min(sizes)
        res['ResourcesMaxSize'] = max(sizes)
    else:
        res['ResourcesNb'] = 0
        res['ResourcesMeanEntropy'] = 0
        res['ResourcesMinEntropy'] = 0
        res['ResourcesMaxEntropy'] = 0
        res['ResourcesMeanSize'] = 0
        res['ResourcesMinSize'] = 0
        res['ResourcesMaxSize'] = 0

    try:
        res['LoadConfigurationSize'] = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size
    except AttributeError:
        res['LoadConfigurationSize'] = 0


    try:
        version_infos = get_version_info(pe)
        res['VersionInformationSize'] = len(version_infos.keys())
    except AttributeError:
        res['VersionInformationSize'] = 0
    return res


def predict_malware_with_analysis(file_path):
    """
    Analyzes a PE file and determines if it is malware with detailed analysis.
    
    Args:
        file_obj: File object of the PE file to analyze
            
    Returns:
        dict: Results containing prediction and analytical data in dashboard-friendly JSON format
    """
    clf = joblib.load('pe_models/classifier.pkl')
    features = pickle.loads(open(os.path.join('pe_models/features.pkl'), 'rb').read())
    
    data = extract_infos(file_path)
    
    pe_features = list(map(lambda x:data[x], features))
    
    result = clf.predict([pe_features])[0]
    
    probability = clf.predict_proba([pe_features])[0]
    
    analysis = {
        "summary": {
            "prediction": "malicious" if int(result) == 1 else "legitimate",
            "prediction_code": int(result),
            "confidence_score": round(float(probability[int(result)]) * 100, 2),
            "confidence_distribution": {
                "legitimate": round(float(probability[0]) * 100, 2),
                "malicious": round(float(probability[1]) * 100, 2)
            }
        },
        "features": {
            "importance_ranking": [],
            "values": {},
            "suspicious_features": []
        },
        "detailed_analysis": []
    }
    
    feature_importance = {
        'DllCharacteristics': 0.181008,
        'Machine': 0.114327,
        'Characteristics': 0.078960,
        'Subsystem': 0.062311,
        'VersionInformationSize': 0.060331,
        'SectionsMaxEntropy': 0.060196,
        'ImageBase': 0.059015,
        'ResourcesMaxEntropy': 0.051068,
        'MajorSubsystemVersion': 0.043120,
        'SizeOfOptionalHeader': 0.041759,
        'MajorOperatingSystemVersion': 0.027296,
        'ResourcesMinEntropy': 0.021602,
        'SectionsMinEntropy': 0.019809
    }
    
    for feature, importance in sorted(feature_importance.items(), key=lambda x: x[1], reverse=True):
        analysis["features"]["importance_ranking"].append({
            "feature": feature,
            "importance_score": round(importance * 100, 2)
        })
    
    for feature in feature_importance:
        if feature in data:
            analysis["features"]["values"][feature] = data[feature]
    
    feature_analysis = []
    
    if 'DllCharacteristics' in data:
        dll_chars = data['DllCharacteristics']
        dll_analysis = {
            "feature_name": "DllCharacteristics",
            "value": dll_chars,
            "hex_value": f"0x{dll_chars:04x}",
            "importance_score": round(feature_importance['DllCharacteristics'] * 100, 2),
            "is_suspicious": False,
            "risk_level": "low",
            "observations": []
        }
        
        if not (dll_chars & 0x0040):
            dll_analysis["observations"].append({
                "finding": "ASLR disabled",
                "description": "This is suspicious as modern legitimate software typically uses ASLR",
                "risk_level": "medium"
            })
            dll_analysis["is_suspicious"] = True
            dll_analysis["risk_level"] = "medium"
        else:
            dll_analysis["observations"].append({
                "finding": "ASLR enabled",
                "description": "This is a good security feature",
                "risk_level": "low"
            })
            
        if not (dll_chars & 0x0100):
            dll_analysis["observations"].append({
                "finding": "DEP/NX disabled",
                "description": "This is suspicious as modern legitimate software typically uses DEP",
                "risk_level": "medium"
            })
            dll_analysis["is_suspicious"] = True
            dll_analysis["risk_level"] = "medium"
        else:
            dll_analysis["observations"].append({
                "finding": "DEP/NX enabled",
                "description": "This is a good security feature",
                "risk_level": "low"
            })
            
        if dll_chars == 0:
            dll_analysis["observations"].append({
                "finding": "No DLL characteristics set",
                "description": "Unusual for modern legitimate software",
                "risk_level": "high"
            })
            dll_analysis["is_suspicious"] = True
            dll_analysis["risk_level"] = "high"
            
        feature_analysis.append(dll_analysis)
        if dll_analysis["is_suspicious"]:
            analysis["features"]["suspicious_features"].append({
                "feature": "DllCharacteristics",
                "risk_level": dll_analysis["risk_level"],
                "value": dll_chars,
                "hex_value": f"0x{dll_chars:04x}"
            })
    
    if 'Machine' in data:
        machine_val = data['Machine']
        
        machine_types = {
            0x014c: 'x86 (32-bit)',
            0x0200: 'IA64 (Itanium)',
            0x8664: 'x64 (AMD64)',
            0x01c4: 'ARM little endian'
        }
        
        machine_name = machine_types.get(machine_val, f'Unknown ({hex(machine_val)})')
        
        machine_analysis = {
            "feature_name": "Machine",
            "value": machine_val,
            "hex_value": f"0x{machine_val:04x}",
            "readable_value": machine_name,
            "importance_score": round(feature_importance['Machine'] * 100, 2),
            "is_suspicious": False,
            "risk_level": "low",
            "observations": [{
                "finding": f"Target architecture: {machine_name}",
                "description": "Identifies the target CPU architecture",
                "risk_level": "info"
            }]
        }
        
        if machine_val not in machine_types:
            machine_analysis["observations"].append({
                "finding": "Unusual/rare machine type",
                "description": "May indicate specialized or crafted malware",
                "risk_level": "high"
            })
            machine_analysis["is_suspicious"] = True
            machine_analysis["risk_level"] = "high"
            
            analysis["features"]["suspicious_features"].append({
                "feature": "Machine",
                "risk_level": "high",
                "value": machine_val,
                "hex_value": f"0x{machine_val:04x}",
                "description": "Unusual machine type"
            })
            
        feature_analysis.append(machine_analysis)
    
    # Characteristics analysis
    if 'Characteristics' in data:
        char_val = data['Characteristics']
        char_analysis = {
            "feature_name": "Characteristics",
            "value": char_val,
            "hex_value": f"0x{char_val:04x}",
            "importance_score": round(feature_importance['Characteristics'] * 100, 2),
            "is_suspicious": False,
            "risk_level": "low",
            "observations": []
        }
        
        characteristics_flags = []
        
        if char_val & 0x0002:
            characteristics_flags.append("EXECUTABLE_IMAGE")
            char_analysis["observations"].append({
                "finding": "File is executable",
                "description": "Normal characteristic for executable files",
                "risk_level": "info"
            })
        
        if char_val & 0x2000:
            characteristics_flags.append("DLL")
            char_analysis["observations"].append({
                "finding": "File is a DLL",
                "description": "File is designed to be loaded as a library",
                "risk_level": "info"
            })
        
        if char_val & 0x0001:
            characteristics_flags.append("RELOCS_STRIPPED")
            char_analysis["observations"].append({
                "finding": "Relocations stripped",
                "description": "Suspicious for modern software, often indicates manually modified PE",
                "risk_level": "high"
            })
            char_analysis["is_suspicious"] = True
            char_analysis["risk_level"] = "high"
            
            analysis["features"]["suspicious_features"].append({
                "feature": "Characteristics",
                "risk_level": "high",
                "value": char_val,
                "hex_value": f"0x{char_val:04x}",
                "description": "Relocations stripped"
            })
        
        char_analysis["flags"] = characteristics_flags
            
        feature_analysis.append(char_analysis)
    
    if 'SectionsMaxEntropy' in data:
        entropy_val = data['SectionsMaxEntropy']
        entropy_analysis = {
            "feature_name": "SectionsMaxEntropy",
            "value": round(entropy_val, 2),
            "importance_score": round(feature_importance['SectionsMaxEntropy'] * 100, 2),
            "is_suspicious": False,
            "risk_level": "low",
            "observations": []
        }
        
        if entropy_val > 7.0:
            entropy_category = "Very High"
            entropy_analysis["observations"].append({
                "finding": f"Very high section entropy ({entropy_val:.2f})",
                "description": "Indicates encryption, packing, or obfuscation",
                "risk_level": "high"
            })
            entropy_analysis["is_suspicious"] = True
            entropy_analysis["risk_level"] = "high"
            
            analysis["features"]["suspicious_features"].append({
                "feature": "SectionsMaxEntropy",
                "risk_level": "high",
                "value": round(entropy_val, 2),
                "description": "Very high entropy indicates obfuscation"
            })
        elif entropy_val > 6.0:
            entropy_category = "High"
            entropy_analysis["observations"].append({
                "finding": f"High section entropy ({entropy_val:.2f})",
                "description": "May indicate compression or resource data",
                "risk_level": "medium"
            })
            entropy_analysis["is_suspicious"] = True
            entropy_analysis["risk_level"] = "medium"
        else:
            entropy_category = "Normal"
            entropy_analysis["observations"].append({
                "finding": f"Normal section entropy ({entropy_val:.2f})",
                "description": "Within expected range for regular software",
                "risk_level": "low"
            })
            
        entropy_analysis["entropy_category"] = entropy_category
        feature_analysis.append(entropy_analysis)
    
    if 'ImageBase' in data:
        image_base = data['ImageBase']
        base_analysis = {
            "feature_name": "ImageBase",
            "value": image_base,
            "hex_value": f"0x{image_base:08x}",
            "importance_score": round(feature_importance['ImageBase'] * 100, 2),
            "is_suspicious": False,
            "risk_level": "low",
            "observations": []
        }
        
        common_bases = {
            0x00400000: "Standard base address for Windows executables",
            0x10000000: "Standard base address for older Windows executables",
            0x01000000: "Less common base address",
        }
        
        if image_base in common_bases:
            base_analysis["observations"].append({
                "finding": common_bases[image_base],
                "description": "Common legitimate base address",
                "risk_level": "low"
            })
            base_analysis["base_category"] = "Standard"
        elif image_base < 0x00400000:
            base_analysis["observations"].append({
                "finding": f"Unusually low image base address (0x{image_base:08x})",
                "description": "Lower base addresses are uncommon in legitimate software",
                "risk_level": "high"
            })
            base_analysis["is_suspicious"] = True
            base_analysis["risk_level"] = "high"
            base_analysis["base_category"] = "Unusual - Low"
            
            analysis["features"]["suspicious_features"].append({
                "feature": "ImageBase",
                "risk_level": "high",
                "value": image_base,
                "hex_value": f"0x{image_base:08x}",
                "description": "Unusually low base address"
            })
        elif image_base > 0x80000000:
            base_analysis["observations"].append({
                "finding": f"High image base address (0x{image_base:08x})",
                "description": "Unusual for 32-bit PE files",
                "risk_level": "medium"
            })
            base_analysis["is_suspicious"] = True
            base_analysis["risk_level"] = "medium"
            base_analysis["base_category"] = "Unusual - High"
        else:
            base_analysis["observations"].append({
                "finding": f"Non-standard image base address (0x{image_base:08x})",
                "description": "Not a common base address but within normal range",
                "risk_level": "low"
            })
            base_analysis["base_category"] = "Non-standard"
            
        feature_analysis.append(base_analysis)
    
    if 'ResourcesMaxEntropy' in data and data.get('ResourcesNb', 0) > 0:
        res_entropy_val = data['ResourcesMaxEntropy']
        res_entropy_analysis = {
            "feature_name": "ResourcesMaxEntropy",
            "value": round(res_entropy_val, 2),
            "importance_score": round(feature_importance['ResourcesMaxEntropy'] * 100, 2),
            "is_suspicious": False,
            "risk_level": "low",
            "observations": []
        }
        
        if res_entropy_val > 7.0:
            res_entropy_analysis["observations"].append({
                "finding": f"Very high resource entropy ({res_entropy_val:.2f})",
                "description": "May indicate encrypted data hidden in resources",
                "risk_level": "high"
            })
            res_entropy_analysis["is_suspicious"] = True
            res_entropy_analysis["risk_level"] = "high"
            res_entropy_analysis["entropy_category"] = "Very High"
            
            analysis["features"]["suspicious_features"].append({
                "feature": "ResourcesMaxEntropy",
                "risk_level": "high",
                "value": round(res_entropy_val, 2),
                "description": "Very high resource entropy indicates hiding"
            })
        elif res_entropy_val > 5.5:
            res_entropy_analysis["observations"].append({
                "finding": f"High resource entropy ({res_entropy_val:.2f})",
                "description": "Common for compressed resources or embedded executables",
                "risk_level": "medium"
            })
            res_entropy_analysis["entropy_category"] = "High"
        else:
            res_entropy_analysis["observations"].append({
                "finding": f"Normal resource entropy ({res_entropy_val:.2f})",
                "description": "Within expected range for regular resources",
                "risk_level": "low"
            })
            res_entropy_analysis["entropy_category"] = "Normal"
            
        feature_analysis.append(res_entropy_analysis)
    
    if 'Subsystem' in data:
        subsystem_val = data['Subsystem']
        
        subsystems = {
            1: "Native - Not designed to run in Windows environment",
            2: "Windows GUI",
            3: "Windows Console",
            5: "OS/2 Console",
            7: "POSIX Console",
            8: "Native Windows 9x driver",
            9: "Windows CE GUI",
            10: "EFI Application",
            11: "EFI Boot Service Driver",
            12: "EFI Runtime Driver",
            13: "EFI ROM Image",
            14: "XBOX",
            16: "Windows Boot Application"
        }
        
        subsystem_name = subsystems.get(subsystem_val, f"Unknown ({subsystem_val})")
        
        subsystem_analysis = {
            "feature_name": "Subsystem",
            "value": subsystem_val,
            "readable_value": subsystem_name,
            "importance_score": round(feature_importance['Subsystem'] * 100, 2),
            "is_suspicious": False,
            "risk_level": "low",
            "observations": [{
                "finding": subsystem_name,
                "description": "",
                "risk_level": "info"
            }]
        }
        
        if subsystem_val in [2, 3]:
            subsystem_analysis["category"] = "Common"
        elif subsystem_val in [9, 10, 11, 12, 16]:
            subsystem_analysis["category"] = "Uncommon"
        elif subsystem_val in [1, 5, 7, 8, 13, 14]:
            subsystem_analysis["category"] = "Rare"
            subsystem_analysis["observations"].append({
                "finding": "Unusual subsystem for normal applications",
                "description": "Possible indicator of specialized malware",
                "risk_level": "medium"
            })
            subsystem_analysis["is_suspicious"] = True
            subsystem_analysis["risk_level"] = "medium"
            
            analysis["features"]["suspicious_features"].append({
                "feature": "Subsystem",
                "risk_level": "medium",
                "value": subsystem_val,
                "readable_value": subsystem_name,
                "description": "Unusual subsystem type"
            })
        else:
            subsystem_analysis["category"] = "Unknown"
            subsystem_analysis["observations"].append({
                "finding": f"Unknown subsystem ({subsystem_val})",
                "description": "Highly suspicious",
                "risk_level": "high"
            })
            subsystem_analysis["is_suspicious"] = True
            subsystem_analysis["risk_level"] = "high"
            
            analysis["features"]["suspicious_features"].append({
                "feature": "Subsystem",
                "risk_level": "high",
                "value": subsystem_val,
                "description": "Unknown subsystem"
            })
            
        feature_analysis.append(subsystem_analysis)
        
    if 'VersionInformationSize' in data:
        version_size = data['VersionInformationSize']
        version_analysis = {
            "feature_name": "VersionInformationSize",
            "value": version_size,
            "importance_score": round(feature_importance['VersionInformationSize'] * 100, 2),
            "is_suspicious": False,
            "risk_level": "low",
            "observations": []
        }
        
        if version_size == 0:
            version_analysis["observations"].append({
                "finding": "No version information",
                "description": "Common in malware to avoid identification",
                "risk_level": "high"
            })
            version_analysis["is_suspicious"] = True
            version_analysis["risk_level"] = "high"
            version_analysis["category"] = "Missing"
            
            analysis["features"]["suspicious_features"].append({
                "feature": "VersionInformationSize",
                "risk_level": "high",
                "value": version_size,
                "description": "No version information"
            })
        elif version_size < 4:
            version_analysis["observations"].append({
                "finding": f"Minimal version information ({version_size} entries)",
                "description": "Suspicious",
                "risk_level": "medium"
            })
            version_analysis["is_suspicious"] = True
            version_analysis["risk_level"] = "medium"
            version_analysis["category"] = "Minimal"
        else:
            version_analysis["observations"].append({
                "finding": f"Contains version information ({version_size} entries)",
                "description": "Common in legitimate software",
                "risk_level": "low" 
            })
            version_analysis["category"] = "Normal"
            
        feature_analysis.append(version_analysis)
    
    for feature in feature_importance:
        if feature in data and not any(fa["feature_name"] == feature for fa in feature_analysis):
            feature_val = data[feature]
            simple_analysis = {
                "feature_name": feature,
                "value": feature_val,
                "importance_score": round(feature_importance[feature] * 100, 2),
                "is_suspicious": False,
                "risk_level": "low",
                "observations": [{
                    "finding": f"{feature} value: {feature_val}",
                    "description": "No specific analysis available",
                    "risk_level": "info"
                }]
            }
            feature_analysis.append(simple_analysis)
    
    analysis["detailed_analysis"] = feature_analysis
    
    suspicious_count = len(analysis["features"]["suspicious_features"])
    high_risk_count = sum(1 for f in analysis["features"]["suspicious_features"] if f.get("risk_level") == "high")
    medium_risk_count = sum(1 for f in analysis["features"]["suspicious_features"] if f.get("risk_level") == "medium")
    
    risk_score = min(100, (high_risk_count * 25) + (medium_risk_count * 10) + (20 if suspicious_count > 0 else 0))
    
    analysis["risk_metrics"] = {
        "total_suspicious_features": suspicious_count,
        "high_risk_features": high_risk_count,
        "medium_risk_features": medium_risk_count,
        "low_risk_features": suspicious_count - high_risk_count - medium_risk_count,
        "risk_score": risk_score,
        "risk_level": "high" if risk_score > 70 else "medium" if risk_score > 30 else "low"
    }
    
    if suspicious_count > 0:
        analysis["summary"]["threat_summary"] = f"Found {suspicious_count} suspicious features with {high_risk_count} high-risk indicators."
    else:
        analysis["summary"]["threat_summary"] = "No highly suspicious features identified, however the overall pattern may still indicate malware."
    
    return analysis
