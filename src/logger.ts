import chalk from 'chalk';

export const c = {
  info: (msg: string) => console.log(chalk.blue('ℹ'), msg),
  success: (msg: string) => console.log(chalk.green('✓'), msg),
  warning: (msg: string) => console.log(chalk.yellow('⚠'), msg),
  error: (msg: string) => console.error(chalk.red('✗'), msg),
  dim: (msg: string) => console.log(chalk.gray(msg)),
  header: (msg: string) => console.log('\n' + chalk.bold.cyan('▶'), chalk.bold(msg)),
  sub: (msg: string) => console.log('  ' + chalk.gray(msg)),
  bullet: (label: string, value: string) => console.log(`  ${chalk.cyan('•')} ${label}: ${chalk.white(value)}`),
};
