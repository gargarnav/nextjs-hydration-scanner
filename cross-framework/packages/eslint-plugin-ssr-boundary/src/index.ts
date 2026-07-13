import { noRawDbInGssp } from './rules/nextjs/no-raw-db-in-gssp.js';
import { noRawDbInRscProps } from './rules/nextjs/no-raw-db-in-rsc-props.js';
import { noRawDbInLoad } from './rules/sveltekit/no-raw-db-in-load.js';
import { noRawDbInLoader } from './rules/remix/no-raw-db-in-loader.js';
import { noRawDbInAsyncData } from './rules/nuxt/no-raw-db-in-async-data.js';

const plugin = {
  meta: {
    name: 'eslint-plugin-ssr-boundary',
    version: '0.1.0',
  },
  rules: {
    'nextjs/no-raw-db-in-gssp': noRawDbInGssp,
    'nextjs/no-raw-db-in-rsc-props': noRawDbInRscProps,
    'sveltekit/no-raw-db-in-load': noRawDbInLoad,
    'remix/no-raw-db-in-loader': noRawDbInLoader,
    'nuxt/no-raw-db-in-async-data': noRawDbInAsyncData,
  },
  configs: {} as Record<string, object>,
};

// Recommended config: Next.js (Pages + App Router)
plugin.configs['recommended-nextjs'] = {
  plugins: { 'ssr-boundary': plugin },
  rules: {
    'ssr-boundary/nextjs/no-raw-db-in-gssp': 'error',
    'ssr-boundary/nextjs/no-raw-db-in-rsc-props': 'error',
  },
};

// Recommended config: SvelteKit
plugin.configs['recommended-sveltekit'] = {
  plugins: { 'ssr-boundary': plugin },
  rules: {
    'ssr-boundary/sveltekit/no-raw-db-in-load': 'error',
  },
};

// Recommended config: Remix
plugin.configs['recommended-remix'] = {
  plugins: { 'ssr-boundary': plugin },
  rules: {
    'ssr-boundary/remix/no-raw-db-in-loader': 'error',
  },
};

// Recommended config: Nuxt
plugin.configs['recommended-nuxt'] = {
  plugins: { 'ssr-boundary': plugin },
  rules: {
    'ssr-boundary/nuxt/no-raw-db-in-async-data': 'error',
  },
};

// All frameworks
plugin.configs['recommended'] = {
  plugins: { 'ssr-boundary': plugin },
  rules: {
    'ssr-boundary/nextjs/no-raw-db-in-gssp': 'error',
    'ssr-boundary/nextjs/no-raw-db-in-rsc-props': 'error',
    'ssr-boundary/sveltekit/no-raw-db-in-load': 'error',
    'ssr-boundary/remix/no-raw-db-in-loader': 'error',
    'ssr-boundary/nuxt/no-raw-db-in-async-data': 'error',
  },
};

export default plugin;
export { plugin };

