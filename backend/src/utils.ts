import { FlowCadenceObject } from "./flow/services/gateway.service";
import { CadenceObject } from "@flowser/types/generated/entities/common";
import { mkdir, rm, stat } from "fs/promises";
const kebabCase = require("kebab-case");

// create directory if it does not already exist
export async function mkdirIfEnoent(path: string) {
  try {
    await stat(path);
    console.debug(`directory "${path}" exists, skipping creation`);
  } catch (e: any) {
    if (e.code === "ENOENT") {
      console.debug(`directory "${path}" not found, creating`);
      await mkdir(path);
    } else {
      throw e;
    }
  }
}

export async function rmdir(path: string) {
  return rm(path, { force: true, recursive: true });
}

export function deserializeCadenceObject(
  cadenceObject: FlowCadenceObject
): CadenceObject {
  if (typeof cadenceObject.value === "string") {
    return CadenceObject.fromJSON({
      type: cadenceObject.type,
      value: cadenceObject.value,
    });
  }
  if (cadenceObject.value instanceof Array) {
    return CadenceObject.fromJSON({
      type: cadenceObject.type,
      children: cadenceObject.value.map((value) =>
        deserializeCadenceObject(value)
      ),
    });
  }
  if (cadenceObject.value instanceof Object) {
    return CadenceObject.fromJSON({
      type: cadenceObject.type,
      children: deserializeCadenceObject(cadenceObject.value),
    });
  }
  throw new Error("Unimplemented cadence type");
}

export type ProtobufLikeObject = {
  toJSON: (value: any) => any;
  fromJSON: (value: any) => any;
};

export function typeOrmProtobufTransformer(protobuf: ProtobufLikeObject) {
  return {
    from: (value: any | null) => {
      if (value === null) {
        return null;
      }
      return value?.["map"] !== undefined
        ? value.map(protobuf.fromJSON)
        : protobuf.fromJSON(value);
    },
    to: (value: any | null) => {
      if (value === null) {
        return null;
      }
      return value?.["map"] !== undefined
        ? value.map(protobuf.toJSON)
        : protobuf.toJSON(value);
    },
  };
}

export function toKebabCase(string: string) {
  const kebab = kebabCase(string);
  // kebabCase("WebkitTransform"); => "-webkit-transform"
  // remove "-" prefix
  return kebab.substring(1, kebab.length).replace(/ /g, "");
}

export function randomString() {
  return `${Math.round(Math.random() * Math.pow(10, 20))}`;
}

export function ensurePrefixedAddress(address: string | null | undefined) {
  return address?.startsWith("0x") ? address : `0x${address}`;
}

export type EntitiesDiff<T> = {
  created: T[];
  updated: T[];
  deleted: T[];
};

export function computeEntitiesDiff<T>(props: {
  primaryKey: keyof T;
  oldEntities: T[];
  newEntities: T[];
  deepCompare?: boolean;
}): EntitiesDiff<T> {
  const newEntitiesLookup = new Map(
    props.newEntities.map((entity) => [entity[props.primaryKey], entity])
  );
  const oldEntitiesLookup = new Map(
    props.oldEntities.map((entity) => [entity[props.primaryKey], entity])
  );

  const created = [];
  const updated = [];
  const deleted = [];
  for (const [primaryKey, entity] of newEntitiesLookup) {
    const isExistingEntity = oldEntitiesLookup.has(primaryKey);
    if (!isExistingEntity) {
      created.push(entity);
    }

    if (!props.deepCompare) {
      updated.push(entity);
    }

    if (areDeepEqualEntities(oldEntitiesLookup.get(primaryKey), entity)) {
      updated.push(entity);
    }
  }
  for (const [primaryKey, entity] of oldEntitiesLookup) {
    if (!newEntitiesLookup.has(primaryKey)) {
      deleted.push(entity);
    }
  }

  return { created, updated, deleted };
}

type ProcessEntitiesDiffOptions<T> = {
  create: (entity: T) => Promise<any>;
  update: (entity: T) => Promise<any>;
  delete: (entity: T) => Promise<any>;
  diff: EntitiesDiff<T>;
};

export async function processEntitiesDiff<T>(
  opts: ProcessEntitiesDiffOptions<T>
) {
  const promises = [];
  for (const entity of opts.diff.created) {
    promises.push(opts.create(entity));
  }
  for (const entity of opts.diff.updated) {
    promises.push(opts.update(entity));
  }
  for (const entity of opts.diff.deleted) {
    promises.push(opts.delete(entity));
  }
  return Promise.all(promises);
}

function areDeepEqualEntities<Entity>(
  firstEntity: Entity,
  secondEntity: Entity
) {
  // Entities may have createdAt and updatedAt fields (if they are a subclass of PollingEntity)
  // We shouldn't compare those fields, because we are interested only in other attributes
  const firstData = JSON.stringify({
    ...firstEntity,
    createdAt: null,
    updatedAt: null,
  });
  const secondData = JSON.stringify({
    ...secondEntity,
    createdAt: null,
    updatedAt: null,
  });
  return firstData === secondData;
}
