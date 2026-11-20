#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <onnxruntime_cxx_api.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace {
constexpr std::size_t kMaxTokens = 512;
std::vector<std::string> chars(const std::string& s) {
    std::vector<std::string> r;
    for (std::size_t i=0;i<s.size();) {
        unsigned char c=static_cast<unsigned char>(s[i]);
        std::size_t n=c<0x80?1:(c&0xE0)==0xC0?2:(c&0xF0)==0xE0?3:(c&0xF8)==0xF0?4:1;
        if(i+n>s.size()) n=1;
        r.emplace_back(s.substr(i,n)); i+=n;
    }
    return r;
}
std::uint32_t cp(const std::string& c) {
    auto b=static_cast<unsigned char>(c[0]);
    if(c.size()==1) return b;
    std::uint32_t v=b&(c.size()==2?0x1F:c.size()==3?0x0F:0x07);
    for(std::size_t i=1;i<c.size();++i) v=(v<<6)|(static_cast<unsigned char>(c[i])&0x3F);
    return v;
}
bool space(std::uint32_t c) {
    return c==32||(c>=9&&c<=13)||c==0xA0||c==0x1680||(c>=0x2000&&c<=0x200A)||
           c==0x2028||c==0x2029||c==0x202F||c==0x205F||c==0x3000;
}
bool cjk(std::uint32_t c) {
    return (c>=0x4E00&&c<=0x9FFF)||(c>=0x3400&&c<=0x4DBF)||(c>=0x3040&&c<=0x30FF)||
           (c>=0x31F0&&c<=0x31FF)||(c>=0xAC00&&c<=0xD7AF)||(c>=0xF900&&c<=0xFAFF)||
           (c>=0x20000&&c<=0x2FA1F);
}
bool punct(std::uint32_t c) {
    return (c>=0x21&&c<=0x2F)||(c>=0x3A&&c<=0x40)||(c>=0x5B&&c<=0x60)||
           (c>=0x7B&&c<=0x7E)||(c>=0x2000&&c<=0x206F)||(c>=0x3001&&c<=0x303F)||
           (c>=0xFF01&&c<=0xFF0F)||(c>=0xFF1A&&c<=0xFF20)||(c>=0xFF3B&&c<=0xFF40)||
           (c>=0xFF5B&&c<=0xFF65);
}
std::vector<std::string> basic_tokens(const std::string& s) {
    std::vector<std::string> out; std::string word;
    auto flush=[&](){if(!word.empty()){out.push_back(word);word.clear();}};
    for(const auto& ch:chars(s)) {
        auto u=cp(ch);
        if(space(u)){flush();continue;}
        if(cjk(u)||punct(u)){flush();out.push_back(ch);} else word+=ch;
    }
    flush(); return out;
}
class Tokenizer {
public:
    explicit Tokenizer(const std::filesystem::path& p) {
        std::ifstream f(p,std::ios::binary); if(!f) throw std::runtime_error("Cannot open vocab.txt");
        std::string line; std::int64_t id=0;
        while(std::getline(f,line)){if(!line.empty()&&line.back()=='\r')line.pop_back();vocab_.emplace(line,id++);}
        for(auto s:{"[UNK]","[CLS]","[SEP]"}) if(!vocab_.contains(s)) throw std::runtime_error("Missing special token in vocab.txt");
    }
    std::vector<std::int64_t> encode(const std::string& s) const {
        std::vector<std::int64_t> ids{vocab_.at("[CLS]")};
        for(const auto& token:basic_tokens(s)) {
            auto pieces=split(token);
            for(const auto& p:pieces){if(ids.size()>=kMaxTokens-1)break;ids.push_back(vocab_.at(p));}
            if(ids.size()>=kMaxTokens-1)break;
        }
        ids.push_back(vocab_.at("[SEP]")); return ids;
    }
private:
    std::vector<std::string> split(const std::string& token) const {
        auto cs=chars(token); if(cs.size()>100)return {"[UNK]"};
        std::vector<std::string> out; std::size_t start=0;
        while(start<cs.size()) {
            bool found=false; std::string chosen; std::size_t finish=start;
            for(std::size_t end=cs.size();end>start;--end) {
                std::string candidate=start?"##":"";
                for(std::size_t i=start;i<end;++i)candidate+=cs[i];
                if(vocab_.contains(candidate)){chosen=candidate;finish=end;found=true;break;}
            }
            if(!found)return {"[UNK]"};
            out.push_back(chosen);start=finish;
        }
        return out;
    }
    std::unordered_map<std::string,std::int64_t> vocab_;
};
class Model {
public:
    explicit Model(const std::filesystem::path& dir):env_(ORT_LOGGING_LEVEL_WARNING,"AntiSpamAI"),tok_(dir/"vocab.txt") {
        auto path=dir/"onnx"/"model_quantized.onnx";
        if(!std::filesystem::exists(path))throw std::runtime_error("ONNX model not found: "+path.string());
        Ort::SessionOptions opt;opt.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_ALL);opt.SetIntraOpNumThreads(2);
        session_=std::make_unique<Ort::Session>(env_,path.c_str(),opt);
        Ort::AllocatorWithDefaultOptions a;
        for(std::size_t i=0;i<session_->GetInputCount();++i){auto n=session_->GetInputNameAllocated(i,a);in_.emplace_back(n.get());}
        for(std::size_t i=0;i<session_->GetOutputCount();++i){auto n=session_->GetOutputNameAllocated(i,a);out_.emplace_back(n.get());}
        if(std::find(in_.begin(),in_.end(),"input_ids")==in_.end()||
           std::find(in_.begin(),in_.end(),"attention_mask")==in_.end()||out_.empty())
            throw std::runtime_error("Unexpected ONNX model input/output signature");
    }
    void classify(const std::string& text,float& ham,float& spam,double& ms) {
        auto t0=std::chrono::steady_clock::now();auto ids=tok_.encode(text);
        std::vector<std::int64_t> mask(ids.size(),1);
        std::array<std::int64_t,2> shape{1,static_cast<std::int64_t>(ids.size())};
        auto mem=Ort::MemoryInfo::CreateCpu(OrtArenaAllocator,OrtMemTypeDefault);
        auto idt=Ort::Value::CreateTensor<std::int64_t>(mem,ids.data(),ids.size(),shape.data(),2);
        auto msk=Ort::Value::CreateTensor<std::int64_t>(mem,mask.data(),mask.size(),shape.data(),2);
        std::vector<Ort::Value> tensors;std::vector<std::vector<std::int64_t>> extras;
        for(const auto& n:in_) {
            if(n=="input_ids")tensors.emplace_back(std::move(idt));
            else if(n=="attention_mask")tensors.emplace_back(std::move(msk));
            else if(n=="token_type_ids"){extras.emplace_back(ids.size(),0);auto& z=extras.back();tensors.emplace_back(Ort::Value::CreateTensor<std::int64_t>(mem,z.data(),z.size(),shape.data(),2));}
            else throw std::runtime_error("Unsupported ONNX input: "+n);
        }
        std::vector<const char*> ins,outs;for(auto& n:in_)ins.push_back(n.c_str());for(auto& n:out_)outs.push_back(n.c_str());
        auto result=session_->Run(Ort::RunOptions{nullptr},ins.data(),tensors.data(),tensors.size(),outs.data(),outs.size());
        if(result.empty()||!result[0].IsTensor())throw std::runtime_error("Model returned no logits tensor");
        auto info=result[0].GetTensorTypeAndShapeInfo();
        if(info.GetElementType()!=ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT||info.GetElementCount()<2)throw std::runtime_error("Unexpected logits shape/type");
        const float* v=result[0].GetTensorData<float>();float mx=std::max(v[0],v[1]);
        double a=std::exp(double(v[0]-mx)),b=std::exp(double(v[1]-mx));ham=float(a/(a+b));spam=float(b/(a+b));
        ms=std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-t0).count();
    }
private:
    Ort::Env env_;Tokenizer tok_;std::unique_ptr<Ort::Session> session_;std::vector<std::string> in_,out_;
};
std::string read_file(const std::filesystem::path& p) {
    std::ifstream f(p,std::ios::binary);if(!f)throw std::runtime_error("Cannot open input file: "+p.string());
    std::string s((std::istreambuf_iterator<char>(f)),{});if(s.size()>1024*1024)throw std::runtime_error("Input exceeds 1 MiB");
    if(s.size()>=3&&(unsigned char)s[0]==0xEF&&(unsigned char)s[1]==0xBB&&(unsigned char)s[2]==0xBF)s.erase(0,3);
    return s;
}
}
int wmain(int argc,wchar_t** argv) {
    try {
        if(argc<3||std::wstring(argv[1])!=L"--classify-file") {
            std::wcerr<<L"Usage: AntiSpamAI.exe --classify-file <UTF-8 text file> [--model-dir <directory>]\n";return 2;
        }
        std::filesystem::path model_dir=L"models\\tanaos-spam-detection-v1";
        if(argc>=5&&std::wstring(argv[3])==L"--model-dir")model_dir=argv[4];
        Model model(model_dir);float ham=0,spam=0;double ms=0;model.classify(read_file(argv[2]),ham,spam,ms);
        std::cout<<"AntiSpamAI manual experiment\nModel: tanaos-spam-detection-v1 (CPU)\n"
                 <<"Result: "<<(spam>=ham?"SPAM":"NOT_SPAM")<<"\n"
                 <<"Spam probability: "<<spam*100.0f<<"%\nNot-spam probability: "<<ham*100.0f
                 <<"%\nInference time: "<<ms<<" ms\n\nExperimental score only; no mail or training data changed.\n";
        return 0;
    } catch(const Ort::Exception& e){std::cerr<<"ONNX Runtime error: "<<e.what()<<"\n";return 3;}
      catch(const std::exception& e){std::cerr<<"Error: "<<e.what()<<"\n";return 4;}
}