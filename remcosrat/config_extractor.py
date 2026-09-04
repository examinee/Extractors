import pefile
import argparse
import json
import os
from remcosrat_field_maps import FIELD_MAPS,normalize,ENUM_PATH,guess


def get_file_info(file_path):
    resource_data= None
    pe = None
    try:
        pe = pefile.PE(file_path)
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                for resource_id in resource_type.directory.entries:
                    if str(resource_id.name) == 'SETTINGS':
                        for resource_lang in resource_id.directory.entries:
                            rva = resource_lang.data.struct.OffsetToData
                            size = resource_lang.data.struct.Size
                            resource_data  = pe.get_data(rva, size)
                            return resource_data
        else:
            return None
    except pefile.PEFormatError:
        return None
    except Exception as e:
        print(f"파일 접근 오류: {e}")
        return None
    finally:
        if pe:
            pe.close()
def extract(data):
    data_list = list(data)
    keylen = data_list[0]
    if not (0 < keylen < len(data_list)):
        print("[!] Abnormal key length")
        return None
    key = data_list[1:1+keylen]
    payload = data_list[keylen+1:]
    return key,payload

def rc4_ksa(key):
    len_key = len(key)
    j = 0
    s_box = list(range(256))
    for i in range(256):
        j = (j + s_box[i] + key[i%len_key]) %256
        s_box[i], s_box[j] = s_box[j], s_box[i]
    return s_box


def rc4_decrypt(key,data,datalen):
    u=0
    y=0
    s_box = rc4_ksa(key)
    for k in range(datalen):
        u = (u+1)%256
        y = (y+ s_box[u]) %256
        s_box[u], s_box[y] = s_box[y],s_box[u]
        l = s_box[(s_box[u] + s_box[y])%256]
        data[k] ^= l
    return data


if __name__ == "__main__":
    result = {}
    parser = argparse.ArgumentParser()
    parser.add_argument('files', nargs='+')
    parser.add_argument('-o', '--output', help='결과를 JSON 파일로 저장')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args()
    if args.output and os.path.exists(args.output):
        print(f"[!] 이미 존재하는 파일입니다: {args.output}")
        exit(1)
    for files in args.files:
        if not os.path.exists(files):
            print(f"[!] 존재하지 않는 파일입니다: {files}")
            continue
        info = get_file_info(files)
        if not info:
            print(f"[!] Resource Field does not exist. file: {files}")
            continue
        parsed = extract(info)
        if parsed is None:
            print(f"[!] Invalid key. file: {files}")
            continue
        key, payload = parsed
        payload_len = len(payload)
        plane_text = rc4_decrypt(key,payload, payload_len)
        DELIM = bytes([0x7C, 0x1E, 0x1E, 0x1F, 0x7C])
        pt = bytes(plane_text)
        version = list(FIELD_MAPS.keys())
        print(f"{os.path.basename(files)} config: RemCos RAT Version {list(version)[0]}")
        json_output = {}
        for idx, f in enumerate(pt.split(DELIM)):
            entry = FIELD_MAPS[version[0]].get(idx)
            if entry:
                json_output[entry[0]] = normalize(f,entry[1])
            else:
                json_output[f"Unknown_Field{idx:02d}"] = guess(f)
        result[os.path.basename(files)] = json_output
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
            print(f"[+] saved: {args.output}")
    elif args.json:
        print(json.dumps(result, indent=2))
    else:
        for fname, cfg in result.items():
            print(f"\n=== {fname} ===")
            for k, v in cfg.items():
                print(f" {k:24s} = {v}")
