import { Anchor, Group, Text, Title } from '@mantine/core';
import type { ReactNode } from 'react';
import { Link } from 'react-router';
import { Icon, type IconName } from '../../design/Icon';
import classes from './ui.module.css';

export interface PageHeaderProps {
  title: ReactNode;
  description?: ReactNode;
  eyebrow?: ReactNode;
  actions?: ReactNode;
  back?: { to: string; label: string };
  icon?: IconName;
  status?: ReactNode;
}

// PageHeader is the design's page head: eyebrow, the page's only <h1>, a one-line description and the page actions.
export function PageHeader({ title, description, eyebrow, actions, back, icon, status }: PageHeaderProps) {
  return (
    <>
      {back && (
        <Anchor component={Link} to={back.to} className={classes.backLink}>
          <Icon name="ArrowLeft" size={14} />
          {back.label}
        </Anchor>
      )}
      <header className={classes.pageHead}>
        <div className={classes.pageHeadText}>
          {eyebrow && <div className={classes.eyebrow}>{eyebrow}</div>}
          <Group gap="sm" wrap="wrap" align="center">
            {icon && (
              <span className={classes.detailIcon}>
                <Icon name={icon} size={23} />
              </span>
            )}
            <Title order={1}>{title}</Title>
            {status}
          </Group>
          {description && <Text className={classes.description}>{description}</Text>}
        </div>
        {actions && (
          <Group gap="xs" className={classes.actions}>
            {actions}
          </Group>
        )}
      </header>
    </>
  );
}
