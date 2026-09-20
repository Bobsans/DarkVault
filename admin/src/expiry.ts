const day = 86400000;
const pad = (value: number) => String(value).padStart(2, '0');
const localDate = (value: Date) => `${value.getFullYear()}-${pad(value.getMonth() + 1)}-${pad(value.getDate())}`;
const localTime = (value: Date) => `${pad(value.getHours())}:${pad(value.getMinutes())}`;

export function nextYear(now: Date) {
    const maximum = new Date(now);
    const lastDay = new Date(Date.UTC(now.getUTCFullYear() + 1, now.getUTCMonth() + 1, 0)).getUTCDate();
    maximum.setUTCFullYear(now.getUTCFullYear() + 1, now.getUTCMonth(), Math.min(now.getUTCDate(), lastDay));
    return maximum;
}

export function setupExpiry(form: HTMLFormElement) {
    const input = form.elements.namedItem('expiry') as HTMLInputElement;
    const preset = document.querySelector<HTMLSelectElement>('#expiry-preset')!;
    const dialog = document.querySelector<HTMLDialogElement>('#expiry-dialog')!;
    const calendar = document.querySelector<HTMLElement>('#expiry-days')!;
    const monthLabel = document.querySelector<HTMLElement>('#expiry-month')!;
    const time = document.querySelector<HTMLInputElement>('#expiry-time')!;
    const error = document.querySelector<HTMLElement>('#expiry-error')!;
    const pickerError = document.querySelector<HTMLElement>('#expiry-picker-error')!;
    const previous = document.querySelector<HTMLButtonElement>('#expiry-previous')!;
    const next = document.querySelector<HTMLButtonElement>('#expiry-next')!;
    const custom = preset.querySelector<HTMLOptionElement>('[value=custom]')!;
    const presets = Array.from(preset.options).filter(option => !['custom', 'choose'].includes(option.value)).map(option => ({ option, label: option.text }));
    let choice = preset.value;
    const initial = new Date(Date.now() + 30 * day);
    input.value = `${localDate(initial)} ${localTime(initial)}`;
    let selected = localDate(initial);
    let month = new Date(initial.getFullYear(), initial.getMonth(), 1);

    function parse(value: string) {
        if (!/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$/.test(value)) return null;
        const date = new Date(value.replace(' ', 'T'));
        return Number.isFinite(date.getTime()) && `${localDate(date)} ${localTime(date)}` === value ? date : null;
    }
    function problem(value: string) {
        const date = parse(value);
        if (!date) return 'Enter a valid local date and time: YYYY-MM-DD HH:mm.';
        const now = Date.now();
        if (date.getTime() <= now) return 'Expiry must be in the future.';
        if (date.getTime() > nextYear(new Date(now)).getTime()) return 'Tokens can expire at most one calendar year from now.';
        return '';
    }
    function validate(report = true) {
        const message = problem(input.value);
        preset.setCustomValidity(message);
        preset.setAttribute('aria-invalid', String(!!message));
        error.textContent = message; error.hidden = !message;
        if (message && report) preset.reportValidity();
        return !message;
    }
    preset.addEventListener('invalid', () => validate(false));
    function presetDate(value: string, now: Date) {
        return value === 'year' ? nextYear(now) : new Date(now.getTime() + Number(value) * 3600000);
    }
    function labelPresets() {
        const now = new Date();
        for (const { option, label } of presets) option.text = `${label} (${presetDate(option.value, now).toLocaleDateString('en', { dateStyle: 'medium' })})`;
    }
    labelPresets();

    function render() {
        const now = new Date(); const maximum = nextYear(now);
        const first = new Date(month.getFullYear(), month.getMonth(), 1);
        const last = new Date(month.getFullYear(), month.getMonth() + 1, 0);
        monthLabel.textContent = first.toLocaleDateString('en', { month: 'long', year: 'numeric' });
        previous.disabled = first <= new Date(now.getFullYear(), now.getMonth(), 1);
        next.disabled = new Date(month.getFullYear(), month.getMonth() + 1, 1) > maximum;
        calendar.replaceChildren();
        for (let date = 1; date <= last.getDate(); date++) {
            const value = new Date(month.getFullYear(), month.getMonth(), date);
            const key = localDate(value);
            const button = document.createElement('button'); button.type = 'button';
            button.textContent = String(date); button.dataset.date = key;
            button.setAttribute('aria-label', value.toLocaleDateString('en', { dateStyle: 'full' }));
            button.setAttribute('aria-pressed', String(key === selected));
            if (key === localDate(now)) button.setAttribute('aria-current', 'date');
            button.disabled = key < localDate(now) || key > localDate(maximum);
            if (date === 1) button.style.gridColumnStart = String((first.getDay() + 6) % 7 + 1);
            button.addEventListener('click', () => { selected = key; pickerError.hidden = true; render(); calendar.querySelector<HTMLButtonElement>(`[data-date="${key}"]`)?.focus(); });
            calendar.append(button);
        }
    }
    previous.addEventListener('click', () => { month.setMonth(month.getMonth() - 1); render(); });
    next.addEventListener('click', () => { month.setMonth(month.getMonth() + 1); render(); });
    function open() {
        const value = parse(input.value);
        const date = value && !problem(input.value) ? value : new Date(Date.now() + 30 * day);
        selected = localDate(date); month = new Date(date.getFullYear(), date.getMonth(), 1);
        time.value = localTime(date); pickerError.hidden = true;
        render(); preset.focus(); dialog.showModal();
        calendar.querySelector<HTMLButtonElement>('[aria-pressed="true"]')?.focus();
    }
    preset.addEventListener('change', () => {
        if (preset.value === 'choose') { preset.value = choice; open(); return; }
        choice = preset.value; custom.hidden = true;
        const value = presetDate(choice, new Date());
        input.value = `${localDate(value)} ${localTime(value)}`; labelPresets(); validate(false);
    });
    document.querySelector('#expiry-cancel')!.addEventListener('click', () => dialog.close());
    document.querySelector('#expiry-picker-form')!.addEventListener('submit', event => {
        event.preventDefault();
        const value = `${selected} ${time.value}`;
        const message = problem(value);
        pickerError.textContent = message; pickerError.hidden = !message;
        if (message) return;
        input.value = value; choice = 'custom'; custom.hidden = false;
        custom.text = parse(value)!.toLocaleString('en', { dateStyle: 'medium', timeStyle: 'short' });
        preset.value = choice; validate(false); dialog.close();
    });
    return { validate, close: () => dialog.close() };
}
