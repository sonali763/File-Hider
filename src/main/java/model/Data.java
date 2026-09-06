package model;

/**
 * Data model representing an encrypted file entry stored in the database.
 */
public class Data {
    private int id;
    private String fileName;
    private String path;
    private String email;
    private byte[] iv;
    private long fileSize;

    public Data(int id, String fileName, String path, String email, byte[] iv, long fileSize) {
        this.id = id;
        this.fileName = fileName;
        this.path = path;
        this.email = email;
        this.iv = iv;
        this.fileSize = fileSize;
    }

    public Data(int id, String fileName, String path, String email) {
        this(id, fileName, path, email, null, 0);
    }

    public Data(int id, String fileName, String path) {
        this(id, fileName, path, null, null, 0);
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public byte[] getIv() {
        return iv;
    }

    public void setIv(byte[] iv) {
        this.iv = iv;
    }

    public long getFileSize() {
        return fileSize;
    }

    public void setFileSize(long fileSize) {
        this.fileSize = fileSize;
    }

    public String getFormattedSize() {
        if (fileSize <= 0) return "0 B";
        final String[] units = new String[] { "B", "KB", "MB", "GB", "TB" };
        int digitGroups = (int) (Math.log10(fileSize) / Math.log10(1024));
        return String.format("%.2f %s", fileSize / Math.pow(1024, digitGroups), units[digitGroups]);
    }
}
