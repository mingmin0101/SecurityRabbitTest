import io
import subprocess

def sigcheck(filepath):
    sigcheck_path = os.path.join(resourceDir,'sigcheck64')
    args = [sigcheck_path,'-i','-nobanner',filepath]
    pipe = subprocess.Popen(args, stdout=subprocess.PIPE)
    sigcheck_output = pipe.communicate()[0]

    sigcheck_str = sigcheck_output.decode('utf-8')
    sigcheck_str = sigcheck_str.replace('\r\n\t','\n').replace(':\t',':').replace('\t','<Certi Info>').replace('  ','<Certificate>')
    sigcheck_dict = {}
    
    verified = False
    if sigcheck_str.find("Verified:Signed") > -1:
        verified = True
    
    if verified:
        temp_queue = []
        #certificate_dict = {}
        certificate_list = []
        sigcheck_str_io = io.StringIO(sigcheck_str)
        for line in sigcheck_str_io:
            if line.find('Signers:') > -1 or line.find('Counter Signers:') > -1:
                pass
            elif line.find("<Certificate>") > -1:

                if len(temp_queue) > 0:
                    certificate_info = temp_queue.copy()
                    temp_queue.clear()
                    certificate_name = certificate_info.pop(0)
                    certificate_list.append(certificate_name)
                    #certificate_dict[certificate_name] = certificate_info
                temp_queue.append(line.replace("<Certificate> ","").replace("\n",""))

            elif line.find("<Certi Info>") > -1:
                temp_queue.append(line.replace("<Certi Info>","").replace("\n",""))
        sigcheck_dict['Signers'] = certificate_list
    
    return sigcheck_dict

if __name__ == "__main__":
    sigcheck()