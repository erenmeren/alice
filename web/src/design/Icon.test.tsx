import { render } from '@testing-library/react';
import { Icon } from './Icon';
import { ICONS } from './icons';

describe('Icon', () => {
  it('draws the icon from its data, hidden from assistive technology', () => {
    const { container } = render(<Icon name="ShieldCheck" size={16} className="x" />);
    const svg = container.querySelector('svg')!;
    expect(svg).toHaveAttribute('aria-hidden', 'true');
    expect(svg).toHaveAttribute('focusable', 'false');
    expect(svg).toHaveAttribute('width', '16');
    expect(svg).toHaveAttribute('stroke', 'currentColor');
    expect(svg).toHaveClass('x');
    expect(svg.children).toHaveLength(ICONS.ShieldCheck.length);
  });
  it('carries the 75 icons of the design (alice-design/dist/icons.js) and nothing that needs innerHTML', () => {
    expect(Object.keys(ICONS)).toHaveLength(75);
    for (const parts of Object.values(ICONS)) for (const [tag] of parts) expect(['path', 'circle', 'rect', 'line', 'ellipse', 'polyline', 'polygon']).toContain(tag);
  });
});
