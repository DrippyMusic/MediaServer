package me.vitormac.mediaserver;

public class ClientException extends RuntimeException {

    private final int status;

    public ClientException(String message) {
        this(message, 400);
    }

    public ClientException(String message, int status) {
        super(message);
        this.status = status;
    }

    public int getStatus() {
        return status;
    }

}
