package com.idp.common.config.json;

import java.io.Reader;
import java.io.Writer;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import org.springframework.http.converter.json.GsonHttpMessageConverter;
import org.springframework.lang.Nullable;
import com.google.gson.Gson;
import com.google.gson.internal.Streams;

public class IdpHttpMessageConverter extends GsonHttpMessageConverter {
    private final Gson gson;

    public IdpHttpMessageConverter(Gson gson) {
        this.gson = gson;
    }

    @Override
    protected Object readInternal(Type resolvedType, Reader reader) throws Exception {
        if (resolvedType.getTypeName().equals(String.class.getTypeName())) {
            char[] cbuf = new char[4096];
            while (reader.read(cbuf) > 0) {
            }

            return new String(cbuf).trim();
        } else {
            return gson.fromJson(reader, resolvedType);
        }
    }

    @Override
    protected void writeInternal(Object object, @Nullable Type type, Writer writer) throws Exception {
        if (object instanceof String) {
            Writer rWriter = Streams.writerForAppendable(writer);
            rWriter.write((String) object);
            rWriter.flush();
        } else {
            if (type instanceof ParameterizedType) {
                gson.toJson(object, type, writer);
            } else {
                gson.toJson(object, writer);
            }
        }

    }
}
