#include "lite_fs.h"
#include "constants.h"
#include "integrity/integrity.h"
#include "lock_guard.h"
#include "logger.h"

#include <cryptopp/base32.h>

#include <cerrno>
#include <mutex>

namespace securefs
{
namespace lite
{
    const std::string DIRID_FILE_NAME = ".securefs.dirid";
    const std::string PATH_SEPARATOR_STRING = "/";

    File::~File() {}

    void File::fstat(struct fuse_stat* stat)
    {
        m_file_stream->fstat(stat);
        stat->st_size = AESGCMCryptStream::calculate_real_size(
            stat->st_size, m_crypt_stream->get_block_size(), m_crypt_stream->get_iv_size());
    }

    FileSystem::FileSystem(std::shared_ptr<const securefs::OSService> root,
                           const key_type& name_key,
                           const key_type& content_key,
                           const key_type& xattr_key,
                           const key_type& padding_key,
                           unsigned block_size,
                           unsigned iv_size,
                           unsigned max_padding_size,
                           unsigned flags)
        : m_content_key(content_key)
        , m_padding_aes(padding_key.data(), padding_key.size())
        , m_root(std::move(root))
        , m_block_size(block_size)
        , m_iv_size(iv_size)
        , m_max_padding_size(max_padding_size)
        , m_flags(flags)
    {
        byte null_iv[12] = {0};
        m_name_encryptor.SetKeyWithIV(name_key.data(), name_key.size(), null_iv, sizeof(null_iv));
        m_name_decryptor.SetKeyWithIV(name_key.data(), name_key.size(), null_iv, sizeof(null_iv));
        m_xattr_enc.SetKeyWithIV(xattr_key.data(), xattr_key.size(), null_iv, sizeof(null_iv));
        m_xattr_dec.SetKeyWithIV(xattr_key.data(), xattr_key.size(), null_iv, sizeof(null_iv));
        // TODO 根据不同操作系统去改变
        i_root = std::make_shared<OSService>("/Users/liang/Downloads/int");
//        i_root = std::make_shared<OSService>("/home/ubuntu/tangrl/experiment/securefs/int");
    }

    FileSystem::~FileSystem() {}

    InvalidFilenameException::~InvalidFilenameException() {}
    std::string InvalidFilenameException::message() const
    {
        return strprintf("Invalid filename \"%s\"", m_filename.c_str());
    }

    std::string encrypt_path(std::shared_ptr<const securefs::OSService> root, CryptoPP::GCM<CryptoPP::AES>::Encryption encryptor, StringRef path)
    {
        byte buffer[2032];
        std::string result;
        result.reserve((path.size() * 8 + 4) / 5);
        size_t last_nonseparator_index = 0;
        std::string encoded_part;

        for (size_t i = 0; i <= path.size(); ++i)
        {
            if (i >= path.size() || path[i] == '/')
            {
                if (i > last_nonseparator_index)
                {
                    const char* slice = path.data() + last_nonseparator_index;
                    size_t slice_size = i - last_nonseparator_index;
                    if (slice_size > 2000)
                        throwVFSException(ENAMETOOLONG);

                    // 从当前result中取出当前目录 id
                    // result + .securefs.dirid
                    std::string dirid_str;
                    if (result.empty()) {
                      dirid_str = DIRID_FILE_NAME;
                    } else {
                      if (result[0] == '/') {
                        dirid_str = result.substr(1) + DIRID_FILE_NAME;
                      } else {
                        dirid_str = result + DIRID_FILE_NAME;
                      }
                    }
                    StringRef dirid_path(dirid_str);
                    auto dirid_file = root->open_file_stream(dirid_path, O_RDONLY, S_IRWXU | S_IRWXG | S_IRWXO);
                    CryptoPP::FixedSizeAlignedSecBlock<byte, 16> id;
                    dirid_file->read(id.data(), 0, id.size());

                    // 加密并拼接加密文件名
                    encryptor.EncryptAndAuthenticate(buffer,
                                                     buffer + slice_size,
                                                     16,
                                                     id.data(),
                                                     12,
                                                     nullptr,
                                                     0,
                                                     reinterpret_cast<const byte*>(slice),
                                                     slice_size);
                    base32_encode(buffer, slice_size + 16, encoded_part);

                    // 添加到result中
                    result.append(encoded_part);
                }
                if (i < path.size())
                    result.push_back('/');
                last_nonseparator_index = i + 1;
            }
        }
        return result;
    }

    std::tuple<std::string, std::unique_ptr<byte[]>, int> encrypt_path_get_name(std::shared_ptr<const securefs::OSService> root, CryptoPP::GCM<CryptoPP::AES>::Encryption encryptor, StringRef path)
    {
        byte buffer[2032];
        std::string result;
        result.reserve((path.size() * 8 + 4) / 5);
        size_t last_nonseparator_index = 0;
        std::string encoded_part;
        std::unique_ptr<byte[]> enc_name;
        int size;

        for (size_t i = 0; i <= path.size(); ++i)
        {
            if (i >= path.size() || path[i] == '/')
            {
                if (i > last_nonseparator_index)
                {
                    const char* slice = path.data() + last_nonseparator_index;
                    size_t slice_size = i - last_nonseparator_index;
                    if (slice_size > 2000)
                        throwVFSException(ENAMETOOLONG);

                    // 从当前result中取出当前目录 id
                    // result + .securefs.dirid
                    std::string dirid_str = result.substr(1) + DIRID_FILE_NAME;
                    StringRef dirid_path(dirid_str);
                    auto dirid_file = root->open_file_stream(dirid_path, O_RDONLY, S_IRWXU | S_IRWXG | S_IRWXO);
                    CryptoPP::FixedSizeAlignedSecBlock<byte, 16> id;
                    dirid_file->read(id.data(), 0, id.size());

                    int enc_data_size = slice_size + 16;
                    // 加密并拼接加密文件名
                    encryptor.EncryptAndAuthenticate(buffer,
                                                     buffer + slice_size,
                                                     16,
                                                     id.data(),
                                                     12,
                                                     nullptr,
                                                     0,
                                                     reinterpret_cast<const byte*>(slice),
                                                     slice_size);
                    base32_encode(buffer, enc_data_size, encoded_part);

                    // 添加到result中
                    result.append(encoded_part);

                    // 如果加密到最后一个文件名，则将其取出
                    if (i == path.size()){
                        enc_name = make_unique_array<byte>(enc_data_size);
                        std::memcpy(enc_name.get(), buffer, enc_data_size);
                        size = enc_data_size;
                    }
                }
                if (i < path.size())
                    result.push_back('/');
                last_nonseparator_index = i + 1;
            }
        }
        return std::make_tuple(result, std::move(enc_name), size);
    }

    std::string decrypt_path(std::shared_ptr<const securefs::OSService> root, CryptoPP::GCM<CryptoPP::AES>::Decryption decryptor, StringRef path)
    {
        byte string_buffer[2032];
        std::string result, decoded_part;
        result.reserve(path.size() * 5 / 8 + 10);
        size_t last_nonseparator_index = 0;

        for (size_t i = 0; i <= path.size(); ++i)
        {
            if (i >= path.size() || path[i] == '/')
            {
                if (i > last_nonseparator_index)
                {
                    const char* slice = path.data() + last_nonseparator_index;
                    size_t slice_size = i - last_nonseparator_index;

                    base32_decode(slice, slice_size, decoded_part);
                    if (decoded_part.size() >= sizeof(string_buffer))
                        throwVFSException(ENAMETOOLONG);

                    // 从当前path中取出当前目录 id
                    // TODO 这部分代码没有调试
                    // 从前往后解密
                    std::string dirid_str;
                    std::string now_path = path.substr(0, last_nonseparator_index);
                    std::size_t pos = now_path.rfind('/');
                    if (pos != std::string::npos) {
                      // 如果找到了反斜杠，提取从开头到反斜杠的位置的子字符串
                      dirid_str =  now_path.substr(0, pos + 1) + DIRID_FILE_NAME;
                    } else {
                      // 如果没有找到反斜杠，直接返回 "dirid"
                      dirid_str =  DIRID_FILE_NAME;
                    }
                    StringRef dirid_path(dirid_str);
                    auto dirid_file = root->open_file_stream(dirid_path, O_RDONLY, S_IRWXU | S_IRWXG | S_IRWXO);
                    CryptoPP::FixedSizeAlignedSecBlock<byte, 16> id;
                    dirid_file->read(id.data(), 0, id.size());

                    int data_size = decoded_part.size() - 16;
                    // 将 decoded_part 进行解密，将解密结果存入到 string_buffer 中，大小为 decoded_part.size()-32
                    bool success = decryptor.DecryptAndVerify(string_buffer,
                                                    reinterpret_cast<const byte*>(&decoded_part[0]) + data_size,
                                                    16,
                                                    id.data(),
                                                    12,
                                                    nullptr,
                                                    0,
                                                    reinterpret_cast<const byte*>(&decoded_part[0]),
                                                    data_size);

                    if (!success)
                        throw InvalidFilenameException(path.to_string());
                    result.append((const char*)string_buffer,
                                  data_size);
                }
                if (i < path.size())
                    result.push_back('/');
                last_nonseparator_index = i + 1;
            }
        }
        return result;
    }

    std::string FileSystem::translate_path(StringRef path, bool preserve_leading_slash)
    {
        if (path.empty())
        {
            return {};
        }
        else if (path.size() == 1 && path[0] == '/')
        {
            if (preserve_leading_slash)
            {
                return "/";
            }
            else
            {
                return ".";
            }
        }
        else
        {
            std::string str = lite::encrypt_path(
                m_root,
                m_name_encryptor,
                transform(path, m_flags & kOptionCaseFoldFileName, m_flags & kOptionNFCFileName)
                    .get());
            if (!preserve_leading_slash && !str.empty() && str[0] == '/')
            {
                str.erase(str.begin());
            }
            TRACE_LOG("Translate path %s into %s", path.c_str(), str.c_str());
            return str;
        }
    }

    // 只对文件用，会获取加密文件名
    std::tuple<std::string, std::unique_ptr<byte[]>, int> FileSystem::translate_path_get_name(StringRef path, bool preserve_leading_slash)
    {
        if (path.empty())
        {
            return {};
        }
        else if (path.size() == 1 && path[0] == '/')
        {
            auto name = make_unique_array<byte>(8);
            std::fill(name.get(), name.get() + 8, 0);
            if (preserve_leading_slash)
            {
                return std::make_tuple("/", std::move(name), 8);
            }
            else
            {
                return std::make_tuple(".", std::move(name), 8);
            }
        }
        else
        {
            std::tuple<std::string, std::unique_ptr<byte[]>, int> result = lite::encrypt_path_get_name(
                m_root,
                m_name_encryptor,
                transform(path, m_flags & kOptionCaseFoldFileName, m_flags & kOptionNFCFileName)
                    .get());

            std::string& str = std::get<0>(result);
            if (!preserve_leading_slash && !str.empty() && str[0] == '/')
            {
                str.erase(str.begin());
            }
            TRACE_LOG("Translate path %s into %s", path.c_str(), str.c_str());
            return result;
        }
    }

    AutoClosedFile FileSystem::open(StringRef path, int flags, fuse_mode_t mode)
    {
        if (flags & O_APPEND)
        {
            flags &= ~((unsigned)O_APPEND);
            // Clear append flags. Workaround for FUSE bug.
            // See https://github.com/netheril96/securefs/issues/58.
        }

        // Files cannot be opened write-only because the header must be read in order to derive the
        // session key
        if ((flags & O_ACCMODE) == O_WRONLY)
        {
            flags = (flags & ~O_ACCMODE) | O_RDWR;
        }
        if ((flags & O_CREAT))
        {
            mode |= S_IRUSR;
        }

        auto result = translate_path_get_name(path, false);

        auto file_stream = m_root->open_file_stream(std::get<0>(result), flags, mode);
        AutoClosedFile fp(new File(file_stream,
                                   i_root,
                                   std::move(std::get<1>(result)),
                                   std::get<2>(result),
                                   m_content_key,
                                   m_block_size,
                                   m_iv_size,
                                   (m_flags & kOptionNoAuthentication) == 0,
                                   m_max_padding_size,
                                   &m_padding_aes));
        if (flags & O_TRUNC)
        {
            LockGuard<File> lock_guard(*fp, true);
            fp->resize(0);
        }
        return fp;
    }

    bool FileSystem::stat(StringRef path, struct fuse_stat* buf)
    {
        auto enc_path = translate_path(path, false);
        if (!m_root->stat(enc_path, buf))
            return false;
        if (buf->st_size <= 0)
            return true;
        switch (buf->st_mode & S_IFMT)
        {
        case S_IFLNK:
        {
            // This is a workaround for Interix symbolic links on NTFS volumes
            // (https://github.com/netheril96/securefs/issues/43).

            // 'buf->st_size' is the expected link size, but on NTFS volumes the link starts with
            // 'IntxLNK\1' followed by the UTF-16 encoded target.
            std::string buffer(buf->st_size, '\0');
            ssize_t link_size = m_root->readlink(enc_path, &buffer[0], buffer.size());
            if (link_size != buf->st_size && link_size != (buf->st_size - 8) / 2)
                throwVFSException(EIO);

            // Resize to actual size
            buffer.resize(static_cast<size_t>(link_size));

            auto resolved = decrypt_path(m_root, m_name_decryptor, buffer);
            buf->st_size = resolved.size();
            break;
        }
        case S_IFDIR:
            break;
        case S_IFREG:
            if (buf->st_size > 0)
            {
                if (m_max_padding_size <= 0)
                {
                    buf->st_size = AESGCMCryptStream::calculate_real_size(
                        buf->st_size, m_block_size, m_iv_size);
                }
                else
                {
                    try
                    {
                        auto fs = m_root->open_file_stream(enc_path, O_RDONLY, 0);
                        AESGCMCryptStream stream(std::move(fs),
                                                 i_root,
                                                 nullptr,
                                                 0,
                                                 m_content_key,
                                                 m_block_size,
                                                 m_iv_size,
                                                 (m_flags & kOptionNoAuthentication) == 0,
                                                 m_max_padding_size,
                                                 &m_padding_aes);
                        buf->st_size = stream.size();
                    }
                    catch (const std::exception& e)
                    {
                        ERROR_LOG("Encountered exception %s when opening file %s for read: %s",
                                  get_type_name(e).get(),
                                  path.c_str(),
                                  e.what());
                    }
                }
            }
            break;
        default:
            throwVFSException(ENOTSUP);
        }
        return true;
    }

    void FileSystem::mkdir(StringRef path, fuse_mode_t mode)
    {
        auto result = translate_path_get_name(path, false);
        std::string& encrypt_path = std::get<0>(result);
        m_root->mkdir(encrypt_path, mode);
        // 在新创建的目录中创建 securefs.dirid 文件，存放这个目录的 id（16字节）
        std::string dirid_str = encrypt_path + PATH_SEPARATOR_STRING + DIRID_FILE_NAME;
        StringRef dirid_path(dirid_str);
        auto dirid_file = m_root->open_file_stream(dirid_path, O_RDWR | O_CREAT, S_IRWXU);
        CryptoPP::FixedSizeAlignedSecBlock<byte, 16> id;
        generate_random(id.data(), id.size());
        dirid_file->write(id.data(), 0, id.size());
        // 存入到hashmap中
        auto& hashmap = integrity::Integrity::getInstance().getHashMap();
        integrity::key_type k(std::get<1>(result).get(), std::get<2>(result));
        integrity::value_type v(id.data());
        hashmap[k] = v;
    }

    void FileSystem::rmdir(StringRef path)
    {
        // 先删除底层存储中的 .securefs.dirid 文件
        auto result = translate_path_get_name(path, false);
        std::string& encrypt_path = std::get<0>(result);
        std::string dirid_str = encrypt_path + PATH_SEPARATOR_STRING + DIRID_FILE_NAME;
        StringRef dirid_path(dirid_str);
        m_root->remove_file(dirid_path);
        // 再删除目录
        m_root->remove_directory(encrypt_path);
        // 从hashmap中删除
        auto& hashmap = integrity::Integrity::getInstance().getHashMap();
        integrity::key_type k(std::get<1>(result).get(), std::get<2>(result));
        hashmap.erase(k);
    }

    void FileSystem::rename(StringRef from, StringRef to)
    {
        // TODO macos 中可能 textedit 使用了 mmap，导致新创建的临时文件的版本号文件没有内容，导致报错（还没有找到具体原因）
        auto to_result = translate_path_get_name(to, false);
        std::string& to_path = std::get<0>(to_result);
        auto from_result = translate_path_get_name(from, false);
        std::string& from_path = std::get<0>(from_result);

        // 从hashmap中读取to，如果存在，删除对应int文件和kv
        auto& hashmap = integrity::Integrity::getInstance().getHashMap();
        integrity::key_type to_k(std::get<1>(to_result).get(), std::get<2>(to_result));
        auto it = hashmap.find(to_k);
        if (it != hashmap.end()) {
            CryptoPP::FixedSizeAlignedSecBlock<byte, 16> id;
            std::memcpy(id.data(), it->second.getData(), 16);
            hashmap.erase(to_k);
            std::string int_path;
            base32_encode(id.data(), id.size(), int_path);
            i_root->remove_file(int_path);
        }
        // 更新kv
        integrity::key_type from_k(std::get<1>(from_result).get(), std::get<2>(from_result));
        auto it2 = hashmap.find(from_k);
        if (it2 != hashmap.end()) {
            integrity::value_type from_v(it2->second);
            hashmap.erase(from_k);
            hashmap[to_k] = from_v;
        }

        m_root->rename(from_path, to_path);
    }

    void FileSystem::chmod(StringRef path, fuse_mode_t mode)
    {
        if (!(mode & S_IRUSR))
        {
            WARN_LOG("Change the mode of file %s to 0%o which denies user read access. "
                     "Mysterious bugs will occur.",
                     path.c_str(),
                     static_cast<unsigned>(mode));
        }
        m_root->chmod(translate_path(path, false), mode);
    }

    void FileSystem::chown(StringRef path, fuse_uid_t uid, fuse_gid_t gid)
    {
        m_root->chown(translate_path(path, false), uid, gid);
    }

    size_t FileSystem::readlink(StringRef path, char* buf, size_t size)
    {
        if (size <= 0)
            return size;

        auto max_size = size / 5 * 8 + 32;
        auto underbuf = securefs::make_unique_array<char>(max_size);
        memset(underbuf.get(), 0, max_size);
        m_root->readlink(translate_path(path, false), underbuf.get(), max_size - 1);
        std::string resolved = decrypt_path(m_root, m_name_decryptor, underbuf.get());
        size_t copy_size = std::min(resolved.size(), size - 1);
        memcpy(buf, resolved.data(), copy_size);
        buf[copy_size] = '\0';
        return copy_size;
    }

    void FileSystem::symlink(StringRef to, StringRef from)
    {
        // TODO 复制符号链接存在问题

        auto eto = translate_path(to, true);
        auto from_result = translate_path_get_name(from, false);
        std::string& efrom = std::get<0>(from_result);
        m_root->symlink(eto, efrom);
        // 将 from 添加到 hashmap 中
        auto& hashmap = integrity::Integrity::getInstance().getHashMap();
        integrity::key_type from_k(std::get<1>(from_result).get(), std::get<2>(from_result));
        integrity::value_type from_v;
        hashmap[from_k] = from_v;

    }

    void FileSystem::utimens(StringRef path, const fuse_timespec* ts)
    {
        m_root->utimens(translate_path(path, false), ts);
    }

    void FileSystem::unlink(StringRef path) {
        auto result = translate_path_get_name(path, false);

        // TODO 如果是符号链接，没有数据文件，不需要删除

        // 删除数据文件
        m_root->remove_file(std::get<0>(result));

        // 从hashmap取出id删除int文件，删除kv，
        if (std::get<1>(result) != nullptr && std::get<2>(result) > 0) {
            auto& hashmap = integrity::Integrity::getInstance().getHashMap();
            integrity::key_type k(std::get<1>(result).get(), std::get<2>(result));
            auto it = hashmap.find(k);
            if (it != hashmap.end()) {
              CryptoPP::FixedSizeAlignedSecBlock<byte, 16> id;
              std::memcpy(id.data(), it->second.getData(), 16);
              std::string int_path;
              base32_encode(id.data(), id.size(), int_path);
              i_root->remove_file(int_path);
              hashmap.erase(k);
            }


        }
    }

    void FileSystem::link(StringRef src, StringRef dest)
    {
        m_root->link(translate_path(src, false), translate_path(dest, false));
    }

    void FileSystem::statvfs(struct fuse_statvfs* buf) { m_root->statfs(buf); }

    class THREAD_ANNOTATION_CAPABILITY("mutex") LiteDirectory final : public Directory
    {
    private:
        std::string m_path;
        std::shared_ptr<const securefs::OSService> m_root;
        std::unique_ptr<DirectoryTraverser>
            m_underlying_traverser THREAD_ANNOTATION_GUARDED_BY(*this);
        CryptoPP::FixedSizeAlignedSecBlock<byte, 16> m_id;
        CryptoPP::GCM<CryptoPP::AES>::Encryption m_name_encryptor THREAD_ANNOTATION_GUARDED_BY(*this);
        CryptoPP::GCM<CryptoPP::AES>::Decryption m_name_decryptor THREAD_ANNOTATION_GUARDED_BY(*this);
        unsigned m_block_size, m_iv_size;


    public:
        explicit LiteDirectory(std::string path,
                               std::shared_ptr<const securefs::OSService> root,
                               std::unique_ptr<DirectoryTraverser> underlying_traverser,
                               CryptoPP::FixedSizeAlignedSecBlock<byte, 16> id,
                               const CryptoPP::GCM<CryptoPP::AES>::Encryption name_encryptor,
                               const CryptoPP::GCM<CryptoPP::AES>::Decryption name_decryptor,
                               unsigned block_size,
                               unsigned iv_size)
            : m_path(std::move(path))
            , m_root(root)
            , m_underlying_traverser(std::move(underlying_traverser))
            , m_id(std::move(id))
            , m_name_encryptor(name_encryptor)
            , m_name_decryptor(name_decryptor)
            , m_block_size(block_size)
            , m_iv_size(iv_size)
        {
        }

        StringRef path() const override { return m_path; }

        void rewind() override THREAD_ANNOTATION_REQUIRES(*this)
        {
            m_underlying_traverser->rewind();
        }

        bool next(std::string* name, struct fuse_stat* stbuf) override
            THREAD_ANNOTATION_REQUIRES(*this)
        {
            std::string under_name, decoded_bytes;

            while (1)
            {
                if (!m_underlying_traverser->next(&under_name, stbuf))
                    return false;
                if (!name)
                    return true;

                if (under_name.empty())
                    continue;
                if (under_name == "." || under_name == "..")
                {
                    if (name)
                        name->swap(under_name);
                    return true;
                }
                if (under_name[0] == '.')
                    continue;
                try
                {
                    base32_decode(under_name.data(), under_name.size(), decoded_bytes);
                    // 读取一个目录项
                    // 判断这个目录项是否在kv中（回滚攻击）
                    auto& hashmap = integrity::Integrity::getInstance().getHashMap();
                    integrity::key_type k(reinterpret_cast<byte*>(&decoded_bytes[0]), decoded_bytes.size());
                    auto it = hashmap.find(k);
                    if (it == hashmap.end()) {
                        throw LiteIntegrityVerificationException();
                    }

                    // 打开文件，会构造加密对象，会去验证id（未对调id攻击）
                    // 其实这个防范是没有必要的，同时对调加密文件名和id，读取目录项也是成功的，只有打开文件读取进行read解密的时候，才会发现用不了

                    if (decoded_bytes.size() <= AES_SIV::IV_SIZE)
                    {
                        WARN_LOG("Skipping too small encrypted filename %s", under_name.c_str());
                        continue;
                    }

                    int data_size = decoded_bytes.size() - 16;

                    name->assign(data_size, '\0');

                    bool success = m_name_decryptor.DecryptAndVerify(reinterpret_cast<byte*>(&(*name)[0]),
                                                              reinterpret_cast<const byte*>(&decoded_bytes[0]) + data_size,
                                                              16,
                                                              m_id.data(),
                                                              12,
                                                              nullptr,
                                                              0,
                                                              reinterpret_cast<const byte*>(&decoded_bytes[0]),
                                                              data_size);

                    if (!success)
                    {
                        WARN_LOG("Skipping filename %s (decrypted to %s) since it fails "
                                 "authentication check",
                                 under_name.c_str(),
                                 name->c_str());
                        continue;
                    }
                    if (stbuf)
                        stbuf->st_size = AESGCMCryptStream::calculate_real_size(
                            stbuf->st_size, m_block_size, m_iv_size);
                }
                catch (const std::exception& e)
                {
                    WARN_LOG("Skipping filename %s due to exception in decoding: %s",
                             under_name.c_str(),
                             e.what());
                    continue;
                }
                return true;
            }
        }
    };

    std::unique_ptr<Directory> FileSystem::opendir(StringRef path)
    {
        if (path.empty())
            throwVFSException(EINVAL);

        auto result = translate_path_get_name(path, false);
        std::string& encrypt_path = std::get<0>(result);
        std::string dirid_str;
        if (encrypt_path == ".") {
            dirid_str = DIRID_FILE_NAME;
        }
        else {
            dirid_str = encrypt_path + PATH_SEPARATOR_STRING + DIRID_FILE_NAME;
        }
        StringRef dirid_path(dirid_str);
        auto dirid_file = m_root->open_file_stream(dirid_path, O_RDONLY, S_IRWXU | S_IRWXG | S_IRWXO);
        CryptoPP::FixedSizeAlignedSecBlock<byte, 16> id;
        dirid_file->read(id.data(), 0, id.size());

        // 比较与kv中的目录是否一致（目录也是文件的一种）
        auto& hashmap = integrity::Integrity::getInstance().getHashMap();
        integrity::key_type k(std::get<1>(result).get(), std::get<2>(result));
        auto it = hashmap.find(k);
        if (it == hashmap.end() || std::memcmp(id.data(), it->second.getData(), 16)) {
            throw LiteIntegrityVerificationException();
        }

        return securefs::make_unique<LiteDirectory>(
            path.to_string(),
            m_root,
            m_root->create_traverser(encrypt_path),
            id,
            this->m_name_encryptor,
            this->m_name_decryptor,
            m_block_size,
            m_iv_size);
    }

    Base::~Base() {}

#ifdef __APPLE__
    ssize_t
    FileSystem::getxattr(const char* path, const char* name, void* buf, size_t size) noexcept
    {
        auto iv_size = m_iv_size;
        auto mac_size = AESGCMCryptStream::get_mac_size();
        if (!buf)
        {
            auto rc = m_root->getxattr(translate_path(path, false).c_str(), name, nullptr, 0);
            if (rc < 0)
            {
                return rc;
            }
            if (rc <= iv_size + mac_size)
            {
                return 0;
            }
            return rc - iv_size - mac_size;
        }

        try
        {
            auto underbuf = securefs::make_unique_array<byte>(size + iv_size + mac_size);
            ssize_t readlen = m_root->getxattr(translate_path(path, false).c_str(),
                                               name,
                                               underbuf.get(),
                                               size + iv_size + mac_size);
            if (readlen <= 0)
                return readlen;
            if (readlen <= iv_size + mac_size)
                return -EIO;
            bool success
                = m_xattr_dec.DecryptAndVerify(static_cast<byte*>(buf),
                                               underbuf.get() + readlen - mac_size,
                                               mac_size,
                                               underbuf.get(),
                                               static_cast<int>(iv_size),
                                               nullptr,
                                               0,
                                               underbuf.get() + iv_size,
                                               static_cast<size_t>(readlen) - iv_size - mac_size);
            if (!success)
            {
                ERROR_LOG("Encrypted extended attribute for file %s and name %s fails "
                          "ciphertext integrity check",
                          path,
                          name);
                return -EIO;
            }
            return readlen - iv_size - mac_size;
        }
        catch (const std::exception& e)
        {
            ERROR_LOG("Error decrypting extended attribute for file %s and name %s (%s)",
                      path,
                      name,
                      e.what());
            return -EIO;
        }
    }

    int FileSystem::setxattr(
        const char* path, const char* name, void* buf, size_t size, int flags) noexcept
    {
        try
        {
            auto iv_size = m_iv_size;
            auto mac_size = AESGCMCryptStream::get_mac_size();
            auto underbuf = securefs::make_unique_array<byte>(size + iv_size + mac_size);
            generate_random(underbuf.get(), iv_size);
            m_xattr_enc.EncryptAndAuthenticate(underbuf.get() + iv_size,
                                               underbuf.get() + iv_size + size,
                                               mac_size,
                                               underbuf.get(),
                                               static_cast<int>(iv_size),
                                               nullptr,
                                               0,
                                               static_cast<const byte*>(buf),
                                               size);
            return m_root->setxattr(translate_path(path, false).c_str(),
                                    name,
                                    underbuf.get(),
                                    size + iv_size + mac_size,
                                    flags);
        }
        catch (const std::exception& e)
        {
            ERROR_LOG("Error encrypting extended attribute for file %s and name %s (%s)",
                      path,
                      name,
                      e.what());
            return -EIO;
        }
    }

#endif
}    // namespace lite
}    // namespace securefs
