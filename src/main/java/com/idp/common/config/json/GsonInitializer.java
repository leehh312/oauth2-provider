package com.idp.common.config.json;

import java.lang.reflect.Modifier;
import java.lang.reflect.Type;
import java.time.Instant;
import java.util.Objects;

import org.bouncycastle.util.encoders.Hex;

import com.google.gson.ExclusionStrategy;
import com.google.gson.FieldAttributes;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;
import com.idp.common.IdpStatus;
import com.idp.common.dto.IdpError;
import com.idp.common.exception.IdpApiException;
import com.idp.common.util.CommonUtils;

public class GsonInitializer {
	private volatile static GsonInitializer instance;
	private Gson gson;
	private GsonBuilder builder;

	private GsonInitializer() {
		this.builder = new GsonBuilder()
				.disableHtmlEscaping()
				.disableInnerClassSerialization()
				.excludeFieldsWithModifiers(Modifier.STATIC, Modifier.TRANSIENT, Modifier.VOLATILE, Modifier.NATIVE)
				.setExclusionStrategies(new GsonAnnotationExclusionStrategy())
				.registerTypeHierarchyAdapter(byte[].class, new ByteArrayToHexStringTypeAdapter())
				.registerTypeHierarchyAdapter(Instant.class, new JavaInstantTypeAdapter());
	}

	public static GsonInitializer getInstance() {
		if (instance == null) {
			synchronized (GsonInitializer.class) {
				if (instance == null) {
					instance = new GsonInitializer();
				}
			}
		}

		return instance;
	}

	public GsonBuilder getBuilder() {
		return builder;
	}

	public void setBuilder(GsonBuilder builder) {
		this.builder = builder;
	}

	public Gson getGson() {
		return this.gson == null ? getBuilder().create() : this.gson;
	}

	public void setGson(Gson gson) {
		this.gson = gson;
	}

	private class GsonAnnotationExclusionStrategy implements ExclusionStrategy {
		@Override
		public boolean shouldSkipField(FieldAttributes f) {
			return Objects.nonNull(f.getAnnotation(GsonIgnore.class));
		}

		@Override
		public boolean shouldSkipClass(Class<?> clazz) {
			return false;
		}
	}

	private static class ByteArrayToHexStringTypeAdapter implements JsonSerializer<byte[]>, JsonDeserializer<byte[]> {
		@Override
		public byte[] deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context)
				throws JsonParseException {
			return Hex.decode(json.getAsString());
		}

		@Override
		public JsonElement serialize(byte[] src, Type typeOfSrc, JsonSerializationContext context) {
			return new JsonPrimitive(Hex.toHexString(src));
		}
	}

	private static class JavaInstantTypeAdapter implements JsonSerializer<Instant>, JsonDeserializer<Instant> {
		@Override
		public Instant deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context)
				throws JsonParseException {
			if (!json.isJsonPrimitive() || !json.getAsJsonPrimitive().isString()) {
				IdpError error = CommonUtils.generateError(IdpStatus.INVALID_JSON_DESEIALIZE_INSTANT);
				throw new IdpApiException(error);
			}
			String text = json.getAsString();

			return Instant.parse(text);
		}

		@Override
		public JsonElement serialize(Instant src, Type typeOfSrc, JsonSerializationContext context) {
			return new JsonPrimitive(src.toString());
		}
	}
}