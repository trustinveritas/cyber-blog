import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

// This runs in Node.js - Don't use client-side code here (browser APIs, JSX...)

const config: Config = {
  title: 'Exploit. Learn. Secure.',
  tagline: 'MHg0MzB4NzkweDYyMHg2NTB4NzIweDIwMHg0MjB4NmMweDZmMHg2Nw==',
  favicon: 'img/favicon.ico',

  // Set the production url of your site here
  url: 'https://blog.salucci.ch/',
  // Set the /<baseUrl>/ pathname under which your site is served
  // For GitHub pages deployment, it is often '/<projectName>/'
  baseUrl: '/',

  // GitHub pages deployment config.
  // If you aren't using GitHub pages, you don't need these.
  organizationName: 'facebook', // Usually your GitHub org/user name.
  projectName: 'docusaurus', // Usually your repo name.

  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'warn',

  // Even if you don't use internationalization, you can use this field to set
  // useful metadata like html lang. For example, if your site is Chinese, you
  // may want to replace "en" with "zh-Hans".
  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          // Please change this to your repo.
          // Remove this to remove the "edit this page" links.
          editUrl:
            'https://github.com/facebook/docusaurus/tree/main/packages/create-docusaurus/templates/shared/',
        },
        blog: {
          showReadingTime: true,
          feedOptions: {
            type: ['rss', 'atom'],
            xslt: true,
          },
          // Please change this to your repo.
          // Remove this to remove the "edit this page" links.
          editUrl:
            'https://github.com/facebook/docusaurus/tree/main/packages/create-docusaurus/templates/shared/',
          // Useful options to enforce blogging best practices
          onInlineTags: 'warn',
          onInlineAuthors: 'warn',
          onUntruncatedBlogPosts: 'warn',
        },
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    // Replace with your project's social card
    image: 'img/this-is-it.png',
    navbar: {
      title: 'Cyber Blog',
      logo: {
        alt: 'My Site Logo',
        src: 'img/logo.png',
      },
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'tutorialSidebar',
          position: 'left',
          label: 'Write-Ups',
        },
        {to: '/blog', label: 'Blog', position: 'left'},
        {
          href: 'https://salucci.ch/',
          label: 'Salucci.ch',
          position: 'left'
        },
        {
          href: 'https://github.com/trustinveritas',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Docs',
          items: [
            {
              label: 'Write-Ups',
              to: '/docs/category/hacking-lab-write-ups',
            },
          ],
        },
        {
          title: 'Socials',
          items: [
            {
              label: 'LinkedIn',
              href: 'https://www.linkedin.com/in/alessandro-salucci/',
            },
            {
              label: 'GitHub Repositories',
              href: 'https://github.com/trustinveritas?tab=repositories',
            },
            {
              label: 'GitHub Portfolio',
              href: 'https://trustinveritas.github.io/',
            },
          ],
        },
        {
          title: 'More',
          items: [
            {
              label: 'Blog',
              to: '/blog',
            },
            {
              label: 'Commercial Register',
              href: 'https://zh.chregister.ch/cr-portal/auszug/auszug.xhtml?uid=CHE-278.357.156#',
            },
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} Salucci CHE-278.357.156, MHg0MzB4NzkweDYyMHg2NTB4NzIweDIwMHg0MjB4NmMweDZmMHg2Nw==,  Built with Docusaurus.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
