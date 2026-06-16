package com.ids.service;

import com.ids.entity.MyWhitelistEntry;
import com.ids.repository.MyWhitelistRepository;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class MyWhitelistService {

    private final MyWhitelistRepository repo;

    public MyWhitelistService(MyWhitelistRepository repo) {
        this.repo = repo;
    }

    public List<MyWhitelistEntry> getAll() { return repo.findAll(); }

    public MyWhitelistEntry add(String ip, String mac, String label) {
        MyWhitelistEntry e = new MyWhitelistEntry();
        e.setIp(ip); e.setMac(mac); e.setLabel(label);
        return repo.save(e);
    }

    public void delete(Long id) { repo.deleteById(id); }
}