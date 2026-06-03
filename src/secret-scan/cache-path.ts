import * as fs from 'fs-extra';
import path from 'path';

export interface CachePathOptions {
  cachePath?: string;
  cache?: boolean;
}

export function resolveCachePath(target: string, options: CachePathOptions): string | undefined {
  if (options.cachePath) {
    return options.cachePath;
  }
  if (!options.cache) {
    return undefined;
  }

  const cacheDir = fs.pathExistsSync(target) && fs.statSync(target).isFile()
    ? path.dirname(target)
    : target;
  return path.join(cacheDir, '.ai-hub-secret-scan-cache.json');
}
